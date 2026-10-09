// Copyright (c) 2026 prt1sn. All rights reserved.
//! pump.fun account layouts (SPEC §3.9): pump_fees `SharingConfig`, pump
//! `BondingCurve`, pump_amm `Pool`, and the buyback readers with the coin
//! checks of SPEC §5.5.2 (strict mode for tag 41, working mode for tags 42
//! (venue switch), 44 and 45; review ACC-2).
//!
//! The readers return a bare [`SijkaError`] without logging, so that callers
//! can map a failure to another error (tags 41 / 42: any pool failure is
//! `BbPoolNotReady`) and still log exactly one line (SPEC §5.0.8). Callers log
//! with `.map_err(SijkaError::fail)`.

use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{
    BONDING_CURVE_DISC, MAX_QUOTE_RESERVE, POOL_DISC, PUMP_AMM_PROGRAM, PUMP_PROGRAM, SEED_AMM_CREATOR_VAULT,
    SEED_PUMP_CREATOR_VAULT, SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_ACCOUNT_LEN,
};
use crate::error::SijkaError;
use crate::util::accounts::token_account_fields_ok;
use crate::util::bytes::{ZERO_KEY, is_zero_key, read_array, read_key, read_u8, read_u16, read_u32, read_u64};
use crate::util::pda::{find, find_ata};

/// pump_fees `SharingConfig` (disc `SHARING_CONFIG_DISC`, U-9, live v2 account).
pub mod sharing_config {
    pub const DISCRIMINATOR: usize = 0;
    pub const BUMP: usize = 8;
    pub const VERSION: usize = 9;
    /// 0 Paused, 1 Active.
    pub const STATUS: usize = 10;
    pub const MINT: usize = 11;
    pub const ADMIN: usize = 43;
    pub const ADMIN_REVOKED: usize = 75;
    /// u32 number of shareholders.
    pub const SHAREHOLDERS_LEN: usize = 76;
    /// Records of 34 bytes (`address [32]`, `share_bps u16`) from here.
    pub const SHAREHOLDERS: usize = 80;
    pub const SHAREHOLDER_LEN: usize = 34;
    pub const SHARE_BPS_IN_RECORD: usize = 32;
}

/// pump `BondingCurve` (disc `BONDING_CURVE_DISC`, ≥ 49 bytes; bytes past the
/// end read as 0). Live length 151 (2026-09-26, U-31); fields are read up to
/// `@125`, the length is never required to be exact.
pub mod bonding_curve {
    pub const DISCRIMINATOR: usize = 0;
    pub const VIRTUAL_TOKEN_RESERVES: usize = 8;
    pub const VIRTUAL_QUOTE_RESERVES: usize = 16;
    pub const REAL_TOKEN_RESERVES: usize = 24;
    pub const REAL_QUOTE_RESERVES: usize = 32;
    pub const COMPLETE: usize = 48;
    pub const CREATOR: usize = 49;
    pub const IS_MAYHEM_MODE: usize = 81;
    pub const IS_CASHBACK_COIN: usize = 82;
    /// Zero for SOL coins.
    pub const QUOTE_MINT: usize = 83;
    /// `creator_fee_bps` (u64): not read since SPEC v4 (DECISIONS §23 item 6).
    pub const CREATOR_FEE_BPS: usize = 115;
    pub const IS_HOLDER_REWARD: usize = 124;
    pub const MIN_LEN: usize = 49;
}

/// pump_amm `Pool` (disc `POOL_DISC`, ≥ 245 bytes; live length 301,
/// 2026-09-26, U-31). Fields are read up to `@271`; the tail after it is not
/// parsed and the length is never required to be exact.
pub mod pool {
    pub const DISCRIMINATOR: usize = 0;
    pub const INDEX: usize = 9;
    pub const CREATOR: usize = 11;
    pub const BASE_MINT: usize = 43;
    pub const QUOTE_MINT: usize = 75;
    pub const POOL_BASE_TOKEN_ACCOUNT: usize = 139;
    pub const POOL_QUOTE_TOKEN_ACCOUNT: usize = 171;
    pub const COIN_CREATOR: usize = 211;
    pub const IS_MAYHEM: usize = 243;
    pub const IS_CASHBACK: usize = 244;
    /// i128, present if `len ≥ 261`.
    pub const VIRTUAL_QUOTE_RESERVES: usize = 245;
    pub const VIRTUAL_QUOTE_RESERVES_END: usize = 261;
    /// u64 `creator_fee_bps`, present if `len ≥ 269`; not read since SPEC v4
    /// (DECISIONS §23 item 6).
    pub const CREATOR_FEE_BPS: usize = 261;
    pub const CREATOR_FEE_BPS_END: usize = 269;
    /// u8, present if `len ≥ 271`.
    pub const HOLDER: usize = 270;
    pub const HOLDER_END: usize = 271;
    pub const MIN_LEN: usize = 245;
}

/// `SharingConfig` fields used by tag 1 (SPEC §5.1.1 step 3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharingConfigFields {
    pub discriminator: [u8; 8],
    pub bump: u8,
    pub version: u8,
    pub status: u8,
    pub mint: Pubkey,
    pub admin_revoked: u8,
    pub shareholders: u32,
    /// First shareholder (address, share_bps), if present.
    pub first: Option<(Pubkey, u16)>,
}

pub fn read_sharing_config(data: &[u8]) -> Option<SharingConfigFields> {
    use sharing_config as s;
    let first_share = s::SHAREHOLDERS.checked_add(s::SHARE_BPS_IN_RECORD)?;
    let first = match (read_key(data, s::SHAREHOLDERS), read_u16(data, first_share)) {
        (Some(k), Some(bps)) => Some((*k, bps)),
        _ => None,
    };
    Some(SharingConfigFields {
        discriminator: read_array::<8>(data, s::DISCRIMINATOR)?,
        bump: read_u8(data, s::BUMP)?,
        version: read_u8(data, s::VERSION)?,
        status: read_u8(data, s::STATUS)?,
        mint: *read_key(data, s::MINT)?,
        admin_revoked: read_u8(data, s::ADMIN_REVOKED)?,
        shareholders: read_u32(data, s::SHAREHOLDERS_LEN)?,
        first,
    })
}

/// `BondingCurve` fields (bytes past the end read as zero, SPEC §3.9).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CurveFields {
    pub virtual_token_reserves: u64,
    pub virtual_quote_reserves: u64,
    pub real_token_reserves: u64,
    pub real_quote_reserves: u64,
    pub complete: u8,
    pub creator: Pubkey,
    pub is_mayhem_mode: u8,
    pub is_cashback_coin: u8,
    pub quote_mint: Pubkey,
    pub is_holder_reward: u8,
}

impl CurveFields {
    /// `complete` flag (any non-zero byte).
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.complete != 0
    }
}

/// Copy of `data` padded with zeros to `N` bytes (curve fields past the end
/// read as 0). Bytes beyond `N` are ignored.
fn padded<const N: usize>(data: &[u8]) -> [u8; N] {
    let mut buf = [0u8; N];
    let n = data.len().min(N);
    if let (Some(dst), Some(src)) = (buf.get_mut(..n), data.get(..n)) {
        dst.copy_from_slice(src);
    }
    buf
}

/// Pure read of curve fields; no owner/disc/length checks (see [`read_curve`]).
pub fn curve_fields(data: &[u8]) -> CurveFields {
    use bonding_curve as c;
    let d = padded::<128>(data);
    CurveFields {
        virtual_token_reserves: read_u64(&d, c::VIRTUAL_TOKEN_RESERVES).unwrap_or(0),
        virtual_quote_reserves: read_u64(&d, c::VIRTUAL_QUOTE_RESERVES).unwrap_or(0),
        real_token_reserves: read_u64(&d, c::REAL_TOKEN_RESERVES).unwrap_or(0),
        real_quote_reserves: read_u64(&d, c::REAL_QUOTE_RESERVES).unwrap_or(0),
        complete: read_u8(&d, c::COMPLETE).unwrap_or(0),
        creator: read_key(&d, c::CREATOR).copied().unwrap_or(ZERO_KEY),
        is_mayhem_mode: read_u8(&d, c::IS_MAYHEM_MODE).unwrap_or(0),
        is_cashback_coin: read_u8(&d, c::IS_CASHBACK_COIN).unwrap_or(0),
        quote_mint: read_key(&d, c::QUOTE_MINT).copied().unwrap_or(ZERO_KEY),
        is_holder_reward: read_u8(&d, c::IS_HOLDER_REWARD).unwrap_or(0),
    }
}

/// Coin checks mode (SPEC §5.5.2, review ACC-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinCheck {
    /// Tag 41 `bb_pin`: mayhem, cashback, holder_reward all zero; creator /
    /// coin_creator equal to the pinned `sharing_config`. The coin's own
    /// `creator_fee_bps` is not checked in any mode (SPEC v4, DECISIONS §23
    /// item 6: a pump fee setting never stops the buyback; the fee goes to the
    /// coin creator, not to a caller).
    Strict,
    /// Tags 42 (venue switch), 44, 45: mayhem, cashback zero; creator /
    /// coin_creator non-zero. `holder_reward` and `creator == sharing_config`
    /// are not checked (pump.fun CTO, ACC-2).
    Working,
    /// Tag 42 on the curve before completion: account checks only (owner,
    /// length, discriminator); the price is only observed, nothing is spent.
    Basic,
}

/// Expected `quote_mint` field of the coin: zero for SOL coins, the USDC mint
/// for USDC coins.
#[inline]
fn expected_quote(usdc_quote: Option<&Pubkey>) -> &Pubkey {
    usdc_quote.unwrap_or(&ZERO_KEY)
}

/// Coin checks of SPEC §5.5.2 on curve fields.
pub fn check_curve_coin(
    f: &CurveFields,
    mode: CoinCheck,
    sharing_config: &Pubkey,
    usdc_quote: Option<&Pubkey>,
) -> Result<(), SijkaError> {
    match mode {
        CoinCheck::Basic => return Ok(()),
        CoinCheck::Strict => {
            if f.is_mayhem_mode != 0 || f.is_cashback_coin != 0 || f.is_holder_reward != 0 {
                return Err(SijkaError::BbCoinFlagsUnexpected);
            }
            if !pubkey_eq(&f.creator, sharing_config) {
                return Err(SijkaError::BbCreatorNotSharing);
            }
        }
        CoinCheck::Working => {
            if f.is_mayhem_mode != 0 || f.is_cashback_coin != 0 {
                return Err(SijkaError::BbCoinFlagsUnexpected);
            }
            if is_zero_key(&f.creator) {
                return Err(SijkaError::BbCreatorNotSharing);
            }
        }
    }
    if !pubkey_eq(&f.quote_mint, expected_quote(usdc_quote)) {
        return Err(SijkaError::BbWrongQuote);
    }
    Ok(())
}

/// `read_curve(acc)`: owner `PUMP_PROGRAM`, `len ≥ 49`, disc
/// (`BbBadPumpAccount`), then the coin checks of `mode`. The caller checks the
/// account key (pinned k11).
pub fn read_curve(
    curve: &AccountInfo,
    mode: CoinCheck,
    sharing_config: &Pubkey,
    usdc_quote: Option<&Pubkey>,
) -> Result<CurveFields, SijkaError> {
    if !curve.is_owned_by(&PUMP_PROGRAM) || curve.data_len() < bonding_curve::MIN_LEN {
        return Err(SijkaError::BbBadPumpAccount);
    }
    let data = curve.try_borrow_data().map_err(|_| SijkaError::InvariantViolated)?;
    if read_array::<8>(&data, bonding_curve::DISCRIMINATOR) != Some(BONDING_CURVE_DISC) {
        return Err(SijkaError::BbBadPumpAccount);
    }
    let f = curve_fields(&data);
    check_curve_coin(&f, mode, sharing_config, usdc_quote)?;
    Ok(f)
}

/// `Pool` fields used by the buyback (SPEC §3.9, §5.5.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolFields {
    pub index: u16,
    pub creator: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub pool_base_token_account: Pubkey,
    pub pool_quote_token_account: Pubkey,
    pub coin_creator: Pubkey,
    pub is_mayhem: u8,
    pub is_cashback: u8,
    /// 0 if the field is absent (`len < 261`).
    pub virtual_quote_reserves: i128,
    /// 0 if absent (`len < 271`).
    pub holder: u8,
}

/// Pure read of pool fields; `None` if `data` is shorter than 245 bytes.
/// Optional tail fields are read only when the data covers them.
pub fn pool_fields(data: &[u8]) -> Option<PoolFields> {
    use pool as p;
    if data.len() < p::MIN_LEN {
        return None;
    }
    let len = data.len();
    let vqr = if len >= p::VIRTUAL_QUOTE_RESERVES_END {
        i128::from_le_bytes(read_array::<16>(data, p::VIRTUAL_QUOTE_RESERVES)?)
    } else {
        0
    };

    let holder = if len >= p::HOLDER_END { read_u8(data, p::HOLDER)? } else { 0 };
    Some(PoolFields {
        index: read_u16(data, p::INDEX)?,
        creator: *read_key(data, p::CREATOR)?,
        base_mint: *read_key(data, p::BASE_MINT)?,
        quote_mint: *read_key(data, p::QUOTE_MINT)?,
        pool_base_token_account: *read_key(data, p::POOL_BASE_TOKEN_ACCOUNT)?,
        pool_quote_token_account: *read_key(data, p::POOL_QUOTE_TOKEN_ACCOUNT)?,
        coin_creator: *read_key(data, p::COIN_CREATOR)?,
        is_mayhem: read_u8(data, p::IS_MAYHEM)?,
        is_cashback: read_u8(data, p::IS_CASHBACK)?,
        virtual_quote_reserves: vqr,
        holder,
    })
}

/// Pinned keys a pool is checked against (SPEC §3.7.1).
#[derive(Clone, Copy)]
pub struct PoolPins<'a> {
    /// k19 `pool_authority` (the canonical pool's `creator`).
    pub pool_authority: &'a Pubkey,
    /// k6 SIJKA mint.
    pub mint: &'a Pubkey,
    /// k7 base token program.
    pub base_token_program: &'a Pubkey,
    /// k8 quote mint.
    pub quote_mint: &'a Pubkey,
    /// k21 / k22 pool token accounts.
    pub base_ta: &'a Pubkey,
    pub quote_ta: &'a Pubkey,
    /// k14 `sharing_config`.
    pub sharing_config: &'a Pubkey,
}

/// Pure pool checks (SPEC §5.5.2 `read_pool`, without the reserves).
pub fn check_pool(
    f: &PoolFields,
    pins: &PoolPins<'_>,
    base_ta_key: &Pubkey,
    quote_ta_key: &Pubkey,
    mode: CoinCheck,
) -> Result<(), SijkaError> {
    let bound = f.index == 0
        && pubkey_eq(&f.creator, pins.pool_authority)
        && pubkey_eq(&f.base_mint, pins.mint)
        && pubkey_eq(&f.quote_mint, pins.quote_mint)
        && pubkey_eq(&f.pool_base_token_account, base_ta_key)
        && pubkey_eq(base_ta_key, pins.base_ta)
        && pubkey_eq(&f.pool_quote_token_account, quote_ta_key)
        && pubkey_eq(quote_ta_key, pins.quote_ta);
    if !bound {
        return Err(SijkaError::BbPinnedAccountMismatch);
    }
    match mode {
        CoinCheck::Strict => {
            if f.is_mayhem != 0 || f.is_cashback != 0 || f.holder != 0 {
                return Err(SijkaError::BbCoinFlagsUnexpected);
            }
            if !pubkey_eq(&f.coin_creator, pins.sharing_config) {
                return Err(SijkaError::BbCreatorNotSharing);
            }
        }
        CoinCheck::Working | CoinCheck::Basic => {
            if f.is_mayhem != 0 || f.is_cashback != 0 {
                return Err(SijkaError::BbCoinFlagsUnexpected);
            }
            if is_zero_key(&f.coin_creator) {
                return Err(SijkaError::BbCreatorNotSharing);
            }
        }
    }
    Ok(())
}

/// Result of [`read_pool`]: fields and the effective reserves `B` (base) and
/// `Q = Qt + virtual_quote_reserves` (quote).
#[derive(Clone, Copy, Debug)]
pub struct PoolRead {
    pub fields: PoolFields,
    pub base: u64,
    pub quote: u64,
}

/// `token_amount(acc, program, mint)` for accounts owned by someone else
/// (pool vaults): owner program, length (Tokenkeg 165, Token-2022 ≥ 165), mint,
/// state Initialized. Delegate and close authority are not ours to check.
fn foreign_token_amount(ai: &AccountInfo, program: &Pubkey, mint: &Pubkey) -> Result<u64, SijkaError> {
    let len_ok = if pubkey_eq(program, &TOKEN_2022_PROGRAM_ID) {
        ai.data_len() >= TOKEN_ACCOUNT_LEN
    } else {
        pubkey_eq(program, &SPL_TOKEN_PROGRAM_ID) && ai.data_len() == TOKEN_ACCOUNT_LEN
    };
    if !ai.is_owned_by(program) || !len_ok {
        return Err(SijkaError::BbBadPumpAccount);
    }
    let data = ai.try_borrow_data().map_err(|_| SijkaError::InvariantViolated)?;
    token_account_fields_ok(&data, mint, None, false, false).ok_or(SijkaError::BbBadPumpAccount)
}

/// `read_pool(pool, base_ta, quote_ta, mode)` (SPEC §5.5.2): owner
/// `PUMP_AMM_PROGRAM`, `len ≥ 245`, disc (`BbBadPumpAccount`); binding to the
/// pinned keys (`BbPinnedAccountMismatch`); coin checks of `mode`;
/// `B = amount(base_ta)`, `Q = amount(quote_ta) + vqr`, with signed checked
/// arithmetic and `0 ≤ Q < 2^63` (`BbReserveAnomaly`). A negative `vqr` can
/// offset fees retained in the quote vault. The caller checks the pool key (k20).
pub fn read_pool(
    pool_ai: &AccountInfo,
    base_ta: &AccountInfo,
    quote_ta: &AccountInfo,
    pins: &PoolPins<'_>,
    mode: CoinCheck,
) -> Result<PoolRead, SijkaError> {
    if !pool_ai.is_owned_by(&PUMP_AMM_PROGRAM) || pool_ai.data_len() < pool::MIN_LEN {
        return Err(SijkaError::BbBadPumpAccount);
    }
    let fields = {
        let data = pool_ai.try_borrow_data().map_err(|_| SijkaError::InvariantViolated)?;
        if read_array::<8>(&data, pool::DISCRIMINATOR) != Some(POOL_DISC) {
            return Err(SijkaError::BbBadPumpAccount);
        }
        pool_fields(&data).ok_or(SijkaError::BbBadPumpAccount)?
    };
    check_pool(&fields, pins, base_ta.key(), quote_ta.key(), mode)?;
    let base = foreign_token_amount(base_ta, pins.base_token_program, pins.mint)?;
    let qt = foreign_token_amount(quote_ta, &SPL_TOKEN_PROGRAM_ID, pins.quote_mint)?;
    let effective_quote =
        i128::from(qt).checked_add(fields.virtual_quote_reserves).ok_or(SijkaError::BbReserveAnomaly)?;
    let quote = u64::try_from(effective_quote).map_err(|_| SijkaError::BbReserveAnomaly)?;
    if quote > MAX_QUOTE_RESERVE {
        return Err(SijkaError::BbReserveAnomaly);
    }
    Ok(PoolRead { fields, base, quote })
}

/// Creator vault of the curve for the live `creator` (SPEC §5.5.2
/// `creator_vault_for`, review ACC-2): the pinned `(k15, k16)` while
/// `creator == k14`, otherwise `PDA(pump, ["creator-vault", creator])` and its
/// quote ATA (Tokenkeg).
pub fn creator_vault_for(
    creator: &Pubkey,
    sharing_config: &Pubkey,
    pinned_vault: &Pubkey,
    pinned_vault_ata: &Pubkey,
    quote_mint: &Pubkey,
) -> Result<(Pubkey, Pubkey), ProgramError> {
    if pubkey_eq(creator, sharing_config) {
        return Ok((*pinned_vault, *pinned_vault_ata));
    }
    let (vault, _) = find(&[SEED_PUMP_CREATOR_VAULT, creator], &PUMP_PROGRAM)?;
    let ata = find_ata(&vault, &SPL_TOKEN_PROGRAM_ID, quote_mint)?;
    Ok((vault, ata))
}

/// PumpSwap coin-creator vault authority and ATA for the live `coin_creator`
/// (SPEC §5.5.2 `coin_creator_vault_for`): the pinned `(k23, k24)` while
/// `coin_creator == k14`, otherwise `PDA(pump_amm, ["creator_vault",
/// coin_creator])` and its quote ATA (Tokenkeg).
pub fn coin_creator_vault_for(
    coin_creator: &Pubkey,
    sharing_config: &Pubkey,
    pinned_authority: &Pubkey,
    pinned_ata: &Pubkey,
    quote_mint: &Pubkey,
) -> Result<(Pubkey, Pubkey), ProgramError> {
    if pubkey_eq(coin_creator, sharing_config) {
        return Ok((*pinned_authority, *pinned_ata));
    }
    let (authority, _) = find(&[SEED_AMM_CREATOR_VAULT, coin_creator], &PUMP_AMM_PROGRAM)?;
    let ata = find_ata(&authority, &SPL_TOKEN_PROGRAM_ID, quote_mint)?;
    Ok((authority, ata))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::constants::{ATA_PROGRAM_ID, WSOL_MINT};
    use crate::util::test_utils::TestAccount;
    use solana_pubkey::Pubkey as SPubkey;

    /// A live-shaped (125-byte) SOL curve with the given reserves and creator.
    pub fn curve_bytes(vt: u64, vq: u64, real_t: u64, creator: &Pubkey) -> Vec<u8> {
        let mut d = vec![0u8; 125];
        d[0..8].copy_from_slice(&BONDING_CURVE_DISC);
        d[8..16].copy_from_slice(&vt.to_le_bytes());
        d[16..24].copy_from_slice(&vq.to_le_bytes());
        d[24..32].copy_from_slice(&real_t.to_le_bytes());
        d[49..81].copy_from_slice(creator);
        d
    }

    /// A live-shaped (271-byte) pool.
    pub fn pool_bytes(pins: &PoolPins<'_>, coin_creator: &Pubkey, vqr: i128) -> Vec<u8> {
        let mut d = vec![0u8; 271];
        d[0..8].copy_from_slice(&POOL_DISC);
        d[11..43].copy_from_slice(pins.pool_authority);
        d[43..75].copy_from_slice(pins.mint);
        d[75..107].copy_from_slice(pins.quote_mint);
        d[139..171].copy_from_slice(pins.base_ta);
        d[171..203].copy_from_slice(pins.quote_ta);
        d[211..243].copy_from_slice(coin_creator);
        d[245..261].copy_from_slice(&vqr.to_le_bytes());
        d
    }

    /// Token account bytes (165).
    pub fn token_bytes(mint: &Pubkey, owner: &Pubkey, amount: u64, native: bool) -> Vec<u8> {
        let mut d = vec![0u8; TOKEN_ACCOUNT_LEN];
        d[0..32].copy_from_slice(mint);
        d[32..64].copy_from_slice(owner);
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d[108] = 1;
        if native {
            d[109..113].copy_from_slice(&1u32.to_le_bytes());
        }
        d
    }

    #[test]
    fn curve_reads_zero_past_end() {
        let mut d = vec![0u8; 49];
        d[8..16].copy_from_slice(&5u64.to_le_bytes());
        d[48] = 1;
        let c = curve_fields(&d);
        assert_eq!(c.virtual_token_reserves, 5);
        assert!(c.is_complete());
        assert_eq!(c.creator, [0u8; 32]);
        assert_eq!(curve_fields(&[]), CurveFields::default());
    }

    #[test]
    fn sharing_config_fields() {
        let mut d = vec![0u8; 114];
        d[9] = 2;
        d[10] = 1;
        d[75] = 1;
        d[76..80].copy_from_slice(&1u32.to_le_bytes());
        d[80..112].copy_from_slice(&[4u8; 32]);
        d[112..114].copy_from_slice(&10_000u16.to_le_bytes());
        let s = read_sharing_config(&d).unwrap();
        assert_eq!((s.version, s.status, s.admin_revoked, s.shareholders), (2, 1, 1, 1));
        assert_eq!(s.first, Some(([4u8; 32], 10_000)));
        assert!(read_sharing_config(&d[..70]).is_none());
    }

    #[test]
    fn curve_coin_checks_by_mode() {
        let sc = [14u8; 32];
        let usdc = [0xC5u8; 32];
        let good = curve_fields(&curve_bytes(1, 1, 1, &sc));
        for mode in [CoinCheck::Strict, CoinCheck::Working, CoinCheck::Basic] {
            assert_eq!(check_curve_coin(&good, mode, &sc, None), Ok(()), "{mode:?}");
        }
        // Quote: SOL coin has a zero quote field; USDC coin must carry the USDC mint.
        assert_eq!(check_curve_coin(&good, CoinCheck::Working, &sc, Some(&usdc)), Err(SijkaError::BbWrongQuote));
        let mut u = good;
        u.quote_mint = usdc;
        assert_eq!(check_curve_coin(&u, CoinCheck::Strict, &sc, Some(&usdc)), Ok(()));
        assert_eq!(check_curve_coin(&u, CoinCheck::Strict, &sc, None), Err(SijkaError::BbWrongQuote));
        // Flags.
        let flag_cases: [fn(&mut CurveFields); 3] =
            [|f| f.is_mayhem_mode = 1, |f| f.is_cashback_coin = 1, |f| f.is_holder_reward = 1];
        for (i, set) in flag_cases.iter().enumerate() {
            let mut f = good;
            set(&mut f);
            assert_eq!(check_curve_coin(&f, CoinCheck::Strict, &sc, None), Err(SijkaError::BbCoinFlagsUnexpected));
            let working = check_curve_coin(&f, CoinCheck::Working, &sc, None);
            if i == 2 {
                // holder_reward is not checked in working mode (ACC-2).
                assert_eq!(working, Ok(()));
            } else {
                assert_eq!(working, Err(SijkaError::BbCoinFlagsUnexpected));
            }
            assert_eq!(check_curve_coin(&f, CoinCheck::Basic, &sc, None), Ok(()));
        }
        // SPEC v4 (DECISIONS §23 item 6): the coin's creator_fee_bps (@115) is
        // never read, so no mode refuses it.
        let mut fee = curve_bytes(1, 1, 1, &sc);
        fee[115..123].copy_from_slice(&300u64.to_le_bytes());
        let with_fee = curve_fields(&fee);
        assert_eq!(with_fee, good);
        for mode in [CoinCheck::Strict, CoinCheck::Working, CoinCheck::Basic] {
            assert_eq!(check_curve_coin(&with_fee, mode, &sc, None), Ok(()), "{mode:?}");
        }
        // Creator after a CTO: strict fails, working passes; zero creator fails both.
        let mut cto = good;
        cto.creator = [0x77; 32];
        assert_eq!(check_curve_coin(&cto, CoinCheck::Strict, &sc, None), Err(SijkaError::BbCreatorNotSharing));
        assert_eq!(check_curve_coin(&cto, CoinCheck::Working, &sc, None), Ok(()));
        cto.creator = [0; 32];
        assert_eq!(check_curve_coin(&cto, CoinCheck::Working, &sc, None), Err(SijkaError::BbCreatorNotSharing));
    }

    #[test]
    fn read_curve_account_checks() {
        let sc = [14u8; 32];
        let d = curve_bytes(1_000, 2_000, 500, &sc);
        let ok = TestAccount::plain([1; 32], PUMP_PROGRAM, &d);
        assert_eq!(read_curve(&ok.info(), CoinCheck::Strict, &sc, None).unwrap().virtual_quote_reserves, 2_000);
        let wrong_owner = TestAccount::plain([1; 32], PUMP_AMM_PROGRAM, &d);
        assert_eq!(read_curve(&wrong_owner.info(), CoinCheck::Basic, &sc, None), Err(SijkaError::BbBadPumpAccount));
        let short = TestAccount::plain([1; 32], PUMP_PROGRAM, &d[..48]);
        assert_eq!(read_curve(&short.info(), CoinCheck::Basic, &sc, None), Err(SijkaError::BbBadPumpAccount));
        let mut bad_disc = d.clone();
        bad_disc[0] ^= 1;
        let b = TestAccount::plain([1; 32], PUMP_PROGRAM, &bad_disc);
        assert_eq!(read_curve(&b.info(), CoinCheck::Basic, &sc, None), Err(SijkaError::BbBadPumpAccount));
        // Old 49-byte curve: tail reads as zero, so strict creator check fails.
        let old = TestAccount::plain([1; 32], PUMP_PROGRAM, &d[..49]);
        assert_eq!(read_curve(&old.info(), CoinCheck::Strict, &sc, None), Err(SijkaError::BbCreatorNotSharing));
    }

    const P_AUTH: Pubkey = [19; 32];
    const P_MINT: Pubkey = [6; 32];
    const P_BASE_TA: Pubkey = [21; 32];
    const P_QUOTE_TA: Pubkey = [22; 32];
    const P_SC: Pubkey = [14; 32];

    fn pins() -> PoolPins<'static> {
        PoolPins {
            pool_authority: &P_AUTH,
            mint: &P_MINT,
            base_token_program: &TOKEN_2022_PROGRAM_ID,
            quote_mint: &WSOL_MINT,
            base_ta: &P_BASE_TA,
            quote_ta: &P_QUOTE_TA,
            sharing_config: &P_SC,
        }
    }

    #[test]
    fn pool_fields_optional_tail() {
        let p = pins();
        let full = pool_bytes(&p, &P_SC, 7);
        let f = pool_fields(&full).unwrap();
        assert_eq!(f.virtual_quote_reserves, 7);
        assert_eq!(f.coin_creator, P_SC);
        // 245 bytes: no vqr, no holder.
        let f = pool_fields(&full[..245]).unwrap();
        assert_eq!((f.virtual_quote_reserves, f.holder), (0, 0));
        // 260 bytes: vqr still absent (needs 261).
        assert_eq!(pool_fields(&full[..260]).unwrap().virtual_quote_reserves, 0);
        assert_eq!(pool_fields(&full[..261]).unwrap().virtual_quote_reserves, 7);
        let mut fee = full.clone();
        fee[261..269].copy_from_slice(&5u64.to_le_bytes());
        fee[270] = 1;
        // creator_fee_bps (@261) is not read (SPEC v4): same fields either way.
        assert_eq!(pool_fields(&fee[..269]), pool_fields(&full[..269]));
        assert_eq!(pool_fields(&fee[..270]).unwrap().holder, 0);
        assert_eq!(pool_fields(&fee).unwrap().holder, 1);
        assert!(pool_fields(&full[..244]).is_none());
    }

    /// Test finding (U-31): live curves are 151 bytes and live pools 301. The
    /// bytes after `@125` / `@271` are ignored and parse exactly like the
    /// 125 / 271-byte shapes.
    #[test]
    fn live_lengths_151_and_301() {
        let sc = [14u8; 32];
        let mut curve = curve_bytes(1_000, 2_000, 900, &sc);
        let short = curve_fields(&curve);
        curve.extend((0..26).map(|i| 0xA0u8.wrapping_add(i)));
        assert_eq!(curve.len(), 151);
        assert_eq!(curve_fields(&curve), short);
        let acc = TestAccount::plain([1; 32], PUMP_PROGRAM, &curve);
        assert_eq!(read_curve(&acc.info(), CoinCheck::Strict, &sc, None), Ok(short));

        let p = pins();
        let mut pool = pool_bytes(&p, &P_SC, 77);
        let short = pool_fields(&pool).unwrap();
        pool.extend((0..30).map(|i| 0xB0u8.wrapping_add(i)));
        assert_eq!(pool.len(), 301);
        assert_eq!(pool_fields(&pool), Some(short));
        assert_eq!(check_pool(&short, &p, &P_BASE_TA, &P_QUOTE_TA, CoinCheck::Strict), Ok(()));
    }

    #[test]
    fn pool_checks_by_mode() {
        let p = pins();
        let good = pool_fields(&pool_bytes(&p, &P_SC, 0)).unwrap();
        for mode in [CoinCheck::Strict, CoinCheck::Working] {
            assert_eq!(check_pool(&good, &p, &P_BASE_TA, &P_QUOTE_TA, mode), Ok(()));
        }
        // Binding to pinned keys.
        let e = Err(SijkaError::BbPinnedAccountMismatch);
        assert_eq!(check_pool(&good, &p, &[1; 32], &P_QUOTE_TA, CoinCheck::Working), e);
        assert_eq!(check_pool(&good, &p, &P_BASE_TA, &[1; 32], CoinCheck::Working), e);
        let muts: [fn(&mut PoolFields); 6] = [
            |f| f.index = 1,
            |f| f.creator = [1; 32],
            |f| f.base_mint = [1; 32],
            |f| f.quote_mint = [1; 32],
            |f| f.pool_base_token_account = [1; 32],
            |f| f.pool_quote_token_account = [1; 32],
        ];
        for m in muts {
            let mut f = good;
            m(&mut f);
            assert_eq!(check_pool(&f, &p, &P_BASE_TA, &P_QUOTE_TA, CoinCheck::Working), e);
        }
        // Coin creator: strict needs sharing_config, working needs non-zero.
        let mut cto = good;
        cto.coin_creator = [0x77; 32];
        assert_eq!(
            check_pool(&cto, &p, &P_BASE_TA, &P_QUOTE_TA, CoinCheck::Strict),
            Err(SijkaError::BbCreatorNotSharing)
        );
        assert_eq!(check_pool(&cto, &p, &P_BASE_TA, &P_QUOTE_TA, CoinCheck::Working), Ok(()));
        cto.coin_creator = [0; 32];
        assert_eq!(
            check_pool(&cto, &p, &P_BASE_TA, &P_QUOTE_TA, CoinCheck::Working),
            Err(SijkaError::BbCreatorNotSharing)
        );
        // SPEC v4: the pool's creator_fee_bps is not a coin check in any mode.
        let mut fee = pool_bytes(&p, &P_SC, 7);
        fee[261..269].copy_from_slice(&300u64.to_le_bytes());
        let with_fee = pool_fields(&fee).unwrap();
        for mode in [CoinCheck::Strict, CoinCheck::Working, CoinCheck::Basic] {
            assert_eq!(check_pool(&with_fee, &p, &P_BASE_TA, &P_QUOTE_TA, mode), Ok(()), "{mode:?}");
        }
        // Holder only in strict mode.
        let mut h = good;
        h.holder = 1;
        assert_eq!(
            check_pool(&h, &p, &P_BASE_TA, &P_QUOTE_TA, CoinCheck::Strict),
            Err(SijkaError::BbCoinFlagsUnexpected)
        );
        assert_eq!(check_pool(&h, &p, &P_BASE_TA, &P_QUOTE_TA, CoinCheck::Working), Ok(()));
        let mut m = good;
        m.is_mayhem = 1;
        assert_eq!(
            check_pool(&m, &p, &P_BASE_TA, &P_QUOTE_TA, CoinCheck::Working),
            Err(SijkaError::BbCoinFlagsUnexpected)
        );
        // Reserve bounds apply to the effective sum in read_pool, not vqr alone.
        let mut v = good;
        v.virtual_quote_reserves = -1;
        assert_eq!(check_pool(&v, &p, &P_BASE_TA, &P_QUOTE_TA, CoinCheck::Working), Ok(()));
        v.virtual_quote_reserves = i128::from(MAX_QUOTE_RESERVE) + 1;
        assert_eq!(check_pool(&v, &p, &P_BASE_TA, &P_QUOTE_TA, CoinCheck::Working), Ok(()));
    }

    #[test]
    fn read_pool_reserves() {
        let p = pins();
        let pool = TestAccount::plain([20; 32], PUMP_AMM_PROGRAM, &pool_bytes(&p, &P_SC, 1_000));
        let base =
            TestAccount::plain(P_BASE_TA, TOKEN_2022_PROGRAM_ID, &token_bytes(&P_MINT, &[20; 32], 5_000_000, false));
        let quote =
            TestAccount::plain(P_QUOTE_TA, SPL_TOKEN_PROGRAM_ID, &token_bytes(&WSOL_MINT, &[20; 32], 9_000, true));
        let r = read_pool(&pool.info(), &base.info(), &quote.info(), &p, CoinCheck::Working).unwrap();
        assert_eq!((r.base, r.quote), (5_000_000, 10_000));
        // Wrong vault owner program / mint.
        let bad = TestAccount::plain(P_BASE_TA, SPL_TOKEN_PROGRAM_ID, &token_bytes(&P_MINT, &[20; 32], 1, false));
        assert_eq!(
            read_pool(&pool.info(), &bad.info(), &quote.info(), &p, CoinCheck::Working).unwrap_err(),
            SijkaError::BbBadPumpAccount
        );
        let wrong_mint =
            TestAccount::plain(P_QUOTE_TA, SPL_TOKEN_PROGRAM_ID, &token_bytes(&[3; 32], &[20; 32], 1, false));
        assert_eq!(
            read_pool(&pool.info(), &base.info(), &wrong_mint.info(), &p, CoinCheck::Working).unwrap_err(),
            SijkaError::BbBadPumpAccount
        );
        // Wrong pool owner.
        let foreign = TestAccount::plain([20; 32], PUMP_PROGRAM, &pool_bytes(&p, &P_SC, 0));
        assert_eq!(
            read_pool(&foreign.info(), &base.info(), &quote.info(), &p, CoinCheck::Working).unwrap_err(),
            SijkaError::BbBadPumpAccount
        );
        // Q overflow past 2^63 − 1.
        let big = TestAccount::plain([20; 32], PUMP_AMM_PROGRAM, &pool_bytes(&p, &P_SC, i128::from(MAX_QUOTE_RESERVE)));
        assert_eq!(
            read_pool(&big.info(), &base.info(), &quote.info(), &p, CoinCheck::Working).unwrap_err(),
            SijkaError::BbReserveAnomaly
        );
    }

    #[test]
    fn read_pool_signed_effective_quote_bounds() {
        let cases = [
            (9_000, -1_000, Ok(8_000)),
            (9_000, 0, Ok(9_000)),
            (9_000, 1_000, Ok(10_000)),
            (9_000, -9_000, Ok(0)),
            (9_000, -9_001, Err(SijkaError::BbReserveAnomaly)),
            (MAX_QUOTE_RESERVE, 0, Ok(MAX_QUOTE_RESERVE)),
            (MAX_QUOTE_RESERVE, 1, Err(SijkaError::BbReserveAnomaly)),
            (u64::MAX, -i128::from(1u64 << 63), Ok(MAX_QUOTE_RESERVE)),
            (u64::MAX, -i128::from(u64::MAX), Ok(0)),
            (u64::MAX, 0, Err(SijkaError::BbReserveAnomaly)),
            (1, i128::MAX, Err(SijkaError::BbReserveAnomaly)),
            (0, i128::MAX, Err(SijkaError::BbReserveAnomaly)),
            (u64::MAX, i128::MIN, Err(SijkaError::BbReserveAnomaly)),
        ];
        // Both quote mints and both supported base-token programs use the same
        // signed formula. Native WSOL and ordinary USDC token vaults are covered.
        const USDC: Pubkey = [0xC5; 32];
        for (quote_mint, native) in [(&WSOL_MINT, true), (&USDC, false)] {
            for base_program in [&TOKEN_2022_PROGRAM_ID, &SPL_TOKEN_PROGRAM_ID] {
                let mut p = pins();
                p.quote_mint = quote_mint;
                p.base_token_program = base_program;
                let base =
                    TestAccount::plain(P_BASE_TA, *base_program, &token_bytes(&P_MINT, &[20; 32], 5_000_000, false));
                for (qt, vqr, expected) in cases {
                    let pool = TestAccount::plain([20; 32], PUMP_AMM_PROGRAM, &pool_bytes(&p, &P_SC, vqr));
                    let quote = TestAccount::plain(
                        P_QUOTE_TA,
                        SPL_TOKEN_PROGRAM_ID,
                        &token_bytes(quote_mint, &[20; 32], qt, native),
                    );
                    for mode in [CoinCheck::Strict, CoinCheck::Working, CoinCheck::Basic] {
                        assert_eq!(
                            read_pool(&pool.info(), &base.info(), &quote.info(), &p, mode).map(|r| r.quote),
                            expected,
                            "qt={qt}, vqr={vqr}, native={native}, mode={mode:?}"
                        );
                    }
                }
                // Old accounts omit the signed tail, which remains equivalent to zero.
                let full = pool_bytes(&p, &P_SC, -1_000);
                let old = TestAccount::plain([20; 32], PUMP_AMM_PROGRAM, &full[..245]);
                let quote = TestAccount::plain(
                    P_QUOTE_TA,
                    SPL_TOKEN_PROGRAM_ID,
                    &token_bytes(quote_mint, &[20; 32], 9_000, native),
                );
                assert_eq!(
                    read_pool(&old.info(), &base.info(), &quote.info(), &p, CoinCheck::Working).unwrap().quote,
                    9_000
                );
            }
        }
    }

    #[test]
    fn creator_vault_derivations_match_pump_seeds() {
        let sc = [14u8; 32];
        let (pv, pa) = ([15u8; 32], [16u8; 32]);
        // Pinned while creator == sharing_config (no syscall).
        assert_eq!(creator_vault_for(&sc, &sc, &pv, &pa, &WSOL_MINT).unwrap(), (pv, pa));
        assert_eq!(coin_creator_vault_for(&sc, &sc, &pv, &pa, &WSOL_MINT).unwrap(), (pv, pa));
        // After a CTO: derived from the live creator.
        let creator = [0x42u8; 32];
        let pump = SPubkey::new_from_array(PUMP_PROGRAM);
        let amm = SPubkey::new_from_array(PUMP_AMM_PROGRAM);
        let ata = SPubkey::new_from_array(ATA_PROGRAM_ID);
        let (v, _) = SPubkey::find_program_address(&[b"creator-vault", &creator], &pump);
        let (va, _) = SPubkey::find_program_address(&[v.as_ref(), &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT], &ata);
        assert_eq!(creator_vault_for(&creator, &sc, &pv, &pa, &WSOL_MINT).unwrap(), (v.to_bytes(), va.to_bytes()));
        let (a, _) = SPubkey::find_program_address(&[b"creator_vault", &creator], &amm);
        let (aa, _) = SPubkey::find_program_address(&[a.as_ref(), &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT], &ata);
        assert_eq!(coin_creator_vault_for(&creator, &sc, &pv, &pa, &WSOL_MINT).unwrap(), (a.to_bytes(), aa.to_bytes()));
    }
}
