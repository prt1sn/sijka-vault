// Copyright (c) 2026 prt1sn. All rights reserved.
//! Instruction shapes and shared entry checks (SPEC §4, §5.0.2–§5.0.4).
//!
//! Rule for every handler (the ABI consistency test relies on it): the first
//! thing a handler does is `check_shape` for its tag / op: exact data length
//! (with declared tails), then exact account count. Only after that come
//! account checks, mode checks and logic. Unknown or reserved tags, unknown
//! ops, wrong lengths and extra accounts are errors (deny by default).
//!
//! The one exception is tag 10 `trade` (SPEC §5.0.2, §5.0.3): its tail is a
//! Phoenix instruction passed through as is, so the shape check only requires
//! the three fixed accounts; the Phoenix part is checked by T3–T10 (§5.2.3).

pub mod buyback;
pub mod harvest;
pub mod inflow;
pub mod recovery;
pub mod setup;
pub mod trade;

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::pubkey_eq;

use crate::constants::{MAX_ATB, MAX_GTI, MAX_JUP_DATA, MAX_ROUTE_ACCOUNTS, MIN_JUP_DATA};
use crate::error::SijkaError;
use crate::state::config::Config;
use crate::util::bytes::{read_u8, read_u16};

/// Variable account tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccTail {
    /// Exactly `accounts` accounts.
    None,
    /// `accounts + g + a` with `g = data[gti_off]`, `a = data[gti_off + 1]`,
    /// each in `1..=8`, else `InvalidArenaAccounts` (SPEC §5.0.5).
    Arenas { gti_off: usize },
    /// `accounts + n` Jupiter route accounts, `1 ≤ n ≤ 64`, else
    /// `JupiterTooManyAccounts` (SPEC §5.3.3 step 1).
    Route,
    /// Tag 10: `accounts + n` accounts of the forwarded Phoenix instruction.
    /// The shape check requires only the fixed part (`InvalidAccountCount`);
    /// `MIN(disc) ≤ n ≤ MAX_TRADE_ACCOUNTS` is rule T4 (`InvalidTradeAccounts`).
    PhoenixIx,
}

/// Variable data tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataTail {
    /// Exactly `data` bytes.
    None,
    /// `data + len` with `len = u16 @len_off`, `min ≤ len ≤ max`, else
    /// `InvalidInstructionData`.
    Bytes { len_off: usize, min: usize, max: usize },
    /// Tag 10: the Phoenix discriminator and payload after the tag, not
    /// parsed. No length check here: data shorter than `data` bytes is
    /// `TradeInstructionNotAllowed` at T3 (SPEC §5.2.3).
    PhoenixIx,
}

/// Shape of one instruction (or one op of tag 51).
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub tag: u8,
    pub op: Option<u8>,
    /// Same name as in `abi/sijka-vault.json`.
    pub name: &'static str,
    /// Fixed accounts.
    pub accounts: usize,
    /// Fixed data bytes (including tag and op).
    pub data: usize,
    pub acc_tail: AccTail,
    pub data_tail: DataTail,
}

/// Tail sizes found by [`check_shape`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShapeInfo {
    pub gti: usize,
    pub atb: usize,
    /// Jupiter route accounts; for tag 10 the Phoenix accounts `n`.
    pub route: usize,
    /// Tail bytes (Jupiter data; for tag 10 the bytes after the fixed 9).
    pub items: usize,
}

const fn arenas(gti_off: usize) -> AccTail {
    AccTail::Arenas { gti_off }
}
const fn shape(tag: u8, op: Option<u8>, name: &'static str, accounts: usize, data: usize) -> Shape {
    Shape { tag, op, name, accounts, data, acc_tail: AccTail::None, data_tail: DataTail::None }
}
const fn with_acc(mut s: Shape, t: AccTail) -> Shape {
    s.acc_tail = t;
    s
}
const fn with_data(mut s: Shape, t: DataTail) -> Shape {
    s.data_tail = t;
    s
}
const JUP_DATA: DataTail = DataTail::Bytes { len_off: 17, min: MIN_JUP_DATA, max: MAX_JUP_DATA };

// ---- setup / admin (SPEC §5.1)
pub const INITIALIZE: Shape = shape(0, None, "initialize", 6, 201);
pub const SET_TOKEN_MINT: Shape = shape(1, None, "set_token_mint", 4, 1);
pub const REGISTER_PHOENIX_TRADER: Shape = shape(2, None, "register_phoenix_trader", 9, 2);
pub const SET_TRADER: Shape = shape(3, None, "set_trader", 2, 33);
// Tags 7 (`set_harvest_params`) and 8 (`renounce_admin`): retired (SPEC v4).
// ---- trading (SPEC §5.2)
pub const TRADE: Shape = with_data(with_acc(shape(10, None, "trade", 3, 9), AccTail::PhoenixIx), DataTail::PhoenixIx);
// ---- inflow (SPEC §5.3)
pub const SWAP_SOL_TO_USDC: Shape =
    with_data(with_acc(shape(20, None, "swap_sol_to_usdc", 10, 19), AccTail::Route), JUP_DATA);
pub const DEPOSIT_USDC: Shape = with_acc(shape(21, None, "deposit_usdc", 15, 11), arenas(1));
pub const SWEEP_FEE_INBOX_USDC: Shape = shape(22, None, "sweep_fee_inbox_usdc", 5, 1);
pub const SWEEP_SWAP_USDC: Shape = shape(23, None, "sweep_swap_usdc", 5, 1);
// Tags 25 (`inflow_set_params`) and 26 (`inflow_set_pause`): retired (SPEC v4).
// ---- keeper key (SPEC §5.1.10, SPEC v4)
pub const SET_KEEPER: Shape = shape(28, None, "set_keeper", 2, 33);
// ---- harvest (SPEC §5.4)
pub const HARVEST: Shape = with_acc(shape(30, None, "harvest", 20, 3), arenas(1));
pub const HARVEST_PREVIEW: Shape = with_acc(shape(31, None, "harvest_preview", 8, 3), arenas(1));
pub const PAY_CREATOR: Shape = shape(32, None, "pay_creator", 5, 1);
// ---- buyback (SPEC §5.5)
pub const BB_INIT: Shape = shape(40, None, "bb_init", 7, 1);
pub const BB_PIN: Shape = shape(41, None, "bb_pin", 7, 1);
pub const BB_OBSERVE: Shape = shape(42, None, "bb_observe", 6, 1);
pub const BB_SWAP_USDC_TO_SOL: Shape =
    with_data(with_acc(shape(43, None, "bb_swap_usdc_to_sol", 15, 19), AccTail::Route), JUP_DATA);
pub const BB_CHUNK_CURVE: Shape = shape(44, None, "bb_chunk_curve", 32, 17);
pub const BB_CHUNK_AMM: Shape = shape(45, None, "bb_chunk_amm", 31, 17);
pub const BB_BURN: Shape = shape(46, None, "bb_burn", 5, 1);
// Tags 47 (`bb_set_params`) and 48 (`bb_set_pause`): retired (SPEC v4).
// ---- emergency recovery (SPEC §5.6)
pub const OBSERVE_VENUE: Shape = shape(50, None, "observe_venue", 5, 1);
pub const RECOVER_LATCH: Shape = shape(51, Some(0), "recover_latch", 5, 2);
pub const RECOVER_WITHDRAW: Shape = with_acc(shape(51, Some(1), "recover_withdraw", 12, 12), arenas(2));
pub const RECOVER_SEND_USDC: Shape = shape(51, Some(2), "recover_send_usdc", 5, 2);
pub const RECOVER_SEND_SOL: Shape = shape(51, Some(3), "recover_send_sol", 4, 2);
pub const RECOVER_UNWRAP: Shape = shape(51, Some(4), "recover_unwrap", 10, 2);
pub const RECOVER_SEND_PHUSD: Shape = shape(51, Some(5), "recover_send_phusd", 5, 2);
pub const RECOVER_WITHDRAW_FLAT: Shape = with_acc(shape(51, Some(6), "recover_withdraw_flat", 11, 12), arenas(2));

/// Every instruction shape, in tag / op order.
pub const SHAPES: &[Shape] = &[
    INITIALIZE,
    SET_TOKEN_MINT,
    REGISTER_PHOENIX_TRADER,
    SET_TRADER,
    TRADE,
    SWAP_SOL_TO_USDC,
    DEPOSIT_USDC,
    SWEEP_FEE_INBOX_USDC,
    SWEEP_SWAP_USDC,
    SET_KEEPER,
    HARVEST,
    HARVEST_PREVIEW,
    PAY_CREATOR,
    BB_INIT,
    BB_PIN,
    BB_OBSERVE,
    BB_SWAP_USDC_TO_SOL,
    BB_CHUNK_CURVE,
    BB_CHUNK_AMM,
    BB_BURN,
    OBSERVE_VENUE,
    RECOVER_LATCH,
    RECOVER_WITHDRAW,
    RECOVER_SEND_USDC,
    RECOVER_SEND_SOL,
    RECOVER_UNWRAP,
    RECOVER_SEND_PHUSD,
    RECOVER_WITHDRAW_FLAT,
];

#[inline(always)]
fn bad_data() -> ProgramError {
    SijkaError::InvalidInstructionData.fail()
}

/// SPEC §5.0.2 / §5.0.3: exact data length (with the declared tail), then
/// exact account count (with the declared tail).
pub fn check_shape(s: &Shape, accounts: &[AccountInfo], data: &[u8]) -> Result<ShapeInfo, ProgramError> {
    let mut info = ShapeInfo::default();

    // Data.
    match s.data_tail {
        DataTail::None => {
            if data.len() != s.data {
                return Err(bad_data());
            }
        }
        DataTail::Bytes { len_off, min, max } => {
            if data.len() < s.data {
                return Err(bad_data());
            }
            let len = usize::from(read_u16(data, len_off).ok_or_else(bad_data)?);
            if len < min || len > max {
                return Err(bad_data());
            }
            if Some(data.len()) != s.data.checked_add(len) {
                return Err(bad_data());
            }
            info.items = len;
        }
        DataTail::PhoenixIx => {
            info.items = data.len().saturating_sub(s.data);
        }
    }

    // Accounts.
    match s.acc_tail {
        AccTail::None => {
            if accounts.len() != s.accounts {
                return Err(SijkaError::InvalidAccountCount.fail());
            }
        }
        AccTail::Arenas { gti_off } => {
            let g = usize::from(read_u8(data, gti_off).ok_or_else(bad_data)?);
            let a_off = gti_off.checked_add(1).ok_or_else(bad_data)?;
            let a = usize::from(read_u8(data, a_off).ok_or_else(bad_data)?);
            if !(1..=MAX_GTI).contains(&g) || !(1..=MAX_ATB).contains(&a) {
                return Err(SijkaError::InvalidArenaAccounts.fail());
            }
            let want = s.accounts.checked_add(g).and_then(|t| t.checked_add(a));
            if Some(accounts.len()) != want {
                return Err(SijkaError::InvalidAccountCount.fail());
            }
            info.gti = g;
            info.atb = a;
        }
        AccTail::Route => {
            let n = accounts.len().checked_sub(s.accounts).ok_or_else(|| SijkaError::InvalidAccountCount.fail())?;
            if n == 0 || n > MAX_ROUTE_ACCOUNTS {
                return Err(SijkaError::JupiterTooManyAccounts.fail());
            }
            info.route = n;
        }
        AccTail::PhoenixIx => {
            let n = accounts.len().checked_sub(s.accounts).ok_or_else(|| SijkaError::InvalidAccountCount.fail())?;
            info.route = n;
        }
    }
    Ok(info)
}

/// Op byte of tag 51 (`data[1]`); a missing op is `InvalidInstructionData`.
#[inline]
pub fn read_op(data: &[u8], off: usize) -> Result<u8, ProgramError> {
    read_u8(data, off).ok_or_else(bad_data)
}

/// Admin check (SPEC §5.0.4), step 1: `accounts[0]` must sign and equal
/// `cfg.admin`, else `Unauthorized`. The admin is never zero (SPEC v4: no
/// `renounce_admin`; `initialize` refuses a zero admin). Step 2
/// (`last_admin_action_ts = now`) is done by the handler on success.
pub fn check_admin(admin: &AccountInfo, cfg: &Config<'_>) -> ProgramResult {
    if !admin.is_signer() || !pubkey_eq(admin.key(), cfg.admin()) {
        return Err(SijkaError::Unauthorized.fail());
    }
    Ok(())
}

/// Keeper check of the swap tags 20 and 43 and the chunk tags 44 and 45 (SPEC
/// §5.3.4, §5.5.7–§5.5.9 step 0, DECISIONS §23 items 3 and 4): `keeper` must
/// sign, `cfg.keeper` must be set (0 = swaps and chunks off) and equal to it,
/// else `UnauthorizedKeeper`. The account is not required to be read-only: the
/// keeper is normally the fee payer.
pub fn check_keeper(keeper: &AccountInfo, cfg: &Config<'_>) -> ProgramResult {
    let k = cfg.keeper();
    if !keeper.is_signer() || crate::util::bytes::is_zero_key(k) || !pubkey_eq(keeper.key(), k) {
        return Err(SijkaError::UnauthorizedKeeper.fail());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DISC_CONFIG;
    use crate::state::config::{CONFIG_LEN, ConfigMut};
    use crate::util::test_utils::{TestAccount, dummy_accounts, infos};

    #[test]
    fn shapes_are_unique_and_sorted() {
        let mut prev: Option<(u8, Option<u8>)> = None;
        for s in SHAPES {
            let k = (s.tag, s.op);
            if let Some(p) = prev {
                assert!(p < k, "{} out of order", s.name);
            }
            prev = Some(k);
        }
    }

    #[test]
    fn arena_counts() {
        let accts = dummy_accounts(40);
        let a = infos(&accts);
        let mut d = vec![0u8; 3];
        d[0] = 31;
        for (g, at, ok) in [(1u8, 1u8, true), (8, 8, true), (0, 1, false), (1, 9, false)] {
            d[1] = g;
            d[2] = at;
            let n = 8 + usize::from(g) + usize::from(at);
            let r = check_shape(&HARVEST_PREVIEW, &a[..n.min(40)], &d);
            if ok {
                assert!(r.is_ok());
                assert_eq!(check_shape(&HARVEST_PREVIEW, &a[..n - 1], &d), Err(SijkaError::InvalidAccountCount.into()));
            } else {
                assert_eq!(r, Err(SijkaError::InvalidArenaAccounts.into()));
            }
        }
    }

    #[test]
    fn route_tail() {
        let accts = dummy_accounts(80);
        let a = infos(&accts);
        let mut d = vec![0u8; 19 + 8];
        d[0] = 20;
        d[17..19].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(check_shape(&SWAP_SOL_TO_USDC, &a[..11], &d).map(|i| (i.route, i.items)), Ok((1, 8)));
        assert_eq!(check_shape(&SWAP_SOL_TO_USDC, &a[..10], &d), Err(SijkaError::JupiterTooManyAccounts.into()));
        assert_eq!(check_shape(&SWAP_SOL_TO_USDC, &a[..9], &d), Err(SijkaError::InvalidAccountCount.into()));
        assert_eq!(check_shape(&SWAP_SOL_TO_USDC, &a[..75], &d), Err(SijkaError::JupiterTooManyAccounts.into()));
        let mut short = d.clone();
        short[17..19].copy_from_slice(&7u16.to_le_bytes());
        short.pop();
        assert_eq!(check_shape(&SWAP_SOL_TO_USDC, &a[..11], &short), Err(SijkaError::InvalidInstructionData.into()));
    }

    #[test]
    fn phoenix_ix_tail() {
        // Tag 10: only the three fixed accounts are required here; the data
        // length is T3's business (`TradeInstructionNotAllowed`), not ours.
        let accts = dummy_accounts(30);
        let a = infos(&accts);
        assert_eq!(check_shape(&TRADE, &a[..2], &[10]), Err(SijkaError::InvalidAccountCount.into()));
        assert_eq!(check_shape(&TRADE, &a[..3], &[10]).map(|i| (i.route, i.items)), Ok((0, 0)));
        let d = [10u8; 40];
        assert_eq!(check_shape(&TRADE, &a[..30], &d).map(|i| (i.route, i.items)), Ok((27, 31)));
        assert_eq!((TRADE.accounts, TRADE.data), (3, 9));
    }

    #[test]
    fn admin_check() {
        let mut buf = vec![0u8; CONFIG_LEN];
        {
            let mut m = ConfigMut::new(&mut buf).unwrap();
            m.set_discriminator(&DISC_CONFIG);
            m.set_version(1);
            m.set_admin(&[7; 32]);
        }
        let cfg = Config::new(&buf).unwrap();
        let ok = TestAccount::new([7; 32], [0; 32], 1, &[], true, false, false);
        let unsigned = TestAccount::new([7; 32], [0; 32], 1, &[], false, false, false);
        let other = TestAccount::new([8; 32], [0; 32], 1, &[], true, false, false);
        assert!(check_admin(&ok.info(), &cfg).is_ok());
        assert_eq!(check_admin(&unsigned.info(), &cfg), Err(SijkaError::Unauthorized.into()));
        assert_eq!(check_admin(&other.info(), &cfg), Err(SijkaError::Unauthorized.into()));
        // A zeroed admin (never written by the program since SPEC v4) matches
        // nobody: a zero key cannot sign.
        ConfigMut::new(&mut buf).unwrap().set_admin(&[0; 32]);
        let cfg = Config::new(&buf).unwrap();
        let zero = TestAccount::new([0; 32], [0; 32], 1, &[], false, false, false);
        assert_eq!(check_admin(&zero.info(), &cfg), Err(SijkaError::Unauthorized.into()));
        assert_eq!(check_admin(&ok.info(), &cfg), Err(SijkaError::Unauthorized.into()));
    }

    #[test]
    fn keeper_check() {
        let mut buf = vec![0u8; CONFIG_LEN];
        {
            let mut m = ConfigMut::new(&mut buf).unwrap();
            m.set_discriminator(&DISC_CONFIG);
            m.set_version(1);
            m.set_admin(&[7; 32]);
            m.set_trader(&[8; 32]);
        }
        let k = TestAccount::new([9; 32], [0; 32], 1, &[], true, true, false);
        let zero_signer = TestAccount::new([0; 32], [0; 32], 1, &[], true, false, false);
        // Keeper not set (0): swaps are off for everybody.
        let cfg = Config::new(&buf).unwrap();
        assert_eq!(check_keeper(&k.info(), &cfg), Err(SijkaError::UnauthorizedKeeper.into()));
        assert_eq!(check_keeper(&zero_signer.info(), &cfg), Err(SijkaError::UnauthorizedKeeper.into()));
        ConfigMut::new(&mut buf).unwrap().set_keeper(&[9; 32]);
        let cfg = Config::new(&buf).unwrap();
        // The keeper, signed and writable (fee payer), passes.
        assert!(check_keeper(&k.info(), &cfg).is_ok());
        // Unsigned, the admin, the trader or anybody else: refused.
        let unsigned = TestAccount::new([9; 32], [0; 32], 1, &[], false, false, false);
        let admin = TestAccount::new([7; 32], [0; 32], 1, &[], true, false, false);
        let trader = TestAccount::new([8; 32], [0; 32], 1, &[], true, false, false);
        for a in [&unsigned, &admin, &trader, &zero_signer] {
            assert_eq!(check_keeper(&a.info(), &cfg), Err(SijkaError::UnauthorizedKeeper.into()));
        }
    }
}
