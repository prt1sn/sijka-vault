// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 10 `trade` (SPEC §5.2, DECISIONS §19): pass-through trading.
//!
//! The trading key `cfg.trader` signs; the program checks that the data holds
//! one of the 14 Phoenix trading instructions of `TRADE_ALLOWLIST` for our
//! trader account `T = (phx_authority, 0, 0)` and forwards it to Phoenix as
//! is, signed by `phx_authority`. There is no market whitelist, price band,
//! size or leverage limit, pause or recovery-mode rule (T13): trading is
//! unrestricted, but only trading goes through. Every other Phoenix
//! instruction (`SwapNative`, `TransferCollateral*`, `WithdrawFunds*`,
//! `DepositFunds`, `DelegateTrader`, `RegisterTrader`, `SyncParentToChild`,
//! escrow, permissions, Phoenix admin) and every other program is rejected.
//!
//! Accounts: `0 trader (S)`, `1 config (R)`, `2 phx_authority`, then
//! `P[0..n]`, the accounts of the Phoenix instruction in Phoenix order
//! (`P[0]` is the Phoenix program itself). Data: `[10] ‖ disc[8] ‖ payload`;
//! `data[1..]` is the Phoenix instruction data and goes to the CPI as is (no
//! intermediate buffer).
//!
//! Tag 10 runs only at the top level of the transaction (T0): a signer
//! privilege carries through CPI, so without it any program invoked in a
//! transaction the trading key signs could call tag 10. Several top-level
//! `trade` instructions in one transaction still work.
//!
//! Rules T0–T12 run in the order of SPEC §5.2.3. Why they are enough (the
//! trader account sits at a fixed slot before the arenas, `phx_authority` is
//! in `P` exactly once and read-only, none of the 14 takes a token account, a
//! token program or a recipient) is SPEC §5.2.5 / appendix H §3, §4.3.
//!
//! After the CPI the handler returns at once (T12): no state write, no
//! `sol_set_return_data`, no event, no second CPI, so Phoenix's own return
//! data (`MatchingEngineCPIResponse`) reaches the client unchanged.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::{AccountMeta, Instruction, Signer};
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{
    AllowedTrade, MAX_TRADE_ACCOUNTS, PHOENIX_GLOBAL_CONFIG, PHOENIX_LOG_AUTHORITY, PHOENIX_PROGRAM_ID,
    SEED_PHX_AUTHORITY, SPL_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TraderWalletSlot,
    allowed_trade,
};
use crate::cpi::PdaSeeds;
use crate::cpi_tramp::cpi_signed;
use crate::error::SijkaError;
use crate::instructions::{TRADE, check_shape};
use crate::state::config::{Config, config_view, load_config};
use crate::util::accounts::expect_readonly;
use crate::util::bytes::is_zero_key;
use crate::util::runtime::require_top_level;

/// Number of fixed accounts before `P` (`trader`, `config`, `phx_authority`).
pub const TRADE_FIXED_ACCOUNTS: usize = 3;
/// Fixed data: tag and the 8-byte Phoenix discriminator.
pub const TRADE_FIXED_DATA: usize = 9;
const _: () = assert!(TRADE.accounts == TRADE_FIXED_ACCOUNTS && TRADE.data == TRADE_FIXED_DATA);

/// What the checks established: the allowlist entry and the index of the
/// Phoenix signer slot in `P` (the only meta the program changes, T11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TradePlan {
    pub rule: AllowedTrade,
    pub wallet: usize,
}

#[inline(always)]
fn ensure(ok: bool, e: SijkaError) -> Result<(), SijkaError> {
    if ok { Ok(()) } else { Err(e) }
}

#[inline(always)]
fn key_at(p: &[AccountInfo], i: usize) -> Option<&Pubkey> {
    p.get(i).map(AccountInfo::key)
}

/// T1–T10 (SPEC §5.2.3) over the loaded `Config`, in the normative order.
/// `trader` and `phx_authority` are fixed slots 0 and 2, `p` the Phoenix
/// accounts (slots 3..), `data` the whole instruction data. Pure: borrows no
/// account data and logs nothing (the caller logs the error).
pub fn check_trade(
    program_id: &Pubkey,
    cfg: &Config<'_>,
    trader: &AccountInfo,
    phx_authority: &AccountInfo,
    p: &[AccountInfo],
    data: &[u8],
) -> Result<TradePlan, SijkaError> {
    // T1: the trading key signs; 0 = trading off.
    ensure(
        trader.is_signer() && !is_zero_key(cfg.trader()) && pubkey_eq(trader.key(), cfg.trader()),
        SijkaError::UnauthorizedTrader,
    )?;
    // T2.
    let t = cfg.phoenix_trader();
    ensure(!is_zero_key(t), SijkaError::TraderNotRegistered)?;
    // Reference slot 2 (its flags do not matter: only `P` goes to the CPI).
    let a = cfg.phx_authority();
    ensure(pubkey_eq(phx_authority.key(), a), SijkaError::InvalidPda)?;

    // T3: the discriminator is one of the 14.
    let disc = data
        .get(1..TRADE_FIXED_DATA)
        .and_then(|d| <[u8; 8]>::try_from(d).ok())
        .map(u64::from_le_bytes)
        .ok_or(SijkaError::TradeInstructionNotAllowed)?;
    let rule = *allowed_trade(disc).ok_or(SijkaError::TradeInstructionNotAllowed)?;

    // T4.
    let n = p.len();
    let bad = SijkaError::InvalidTradeAccounts;
    ensure(n >= rule.min_accounts && n <= MAX_TRADE_ACCOUNTS, bad)?;

    // T5: keys only; owner, data and flags are Phoenix's business.
    ensure(key_at(p, 0) == Some(&PHOENIX_PROGRAM_ID), bad)?;
    ensure(key_at(p, 1) == Some(&PHOENIX_LOG_AUTHORITY), bad)?;
    ensure(key_at(p, 2) == Some(&PHOENIX_GLOBAL_CONFIG), bad)?;

    // T6: our trader account at its fixed slot.
    ensure(key_at(p, rule.trader).is_some_and(|k| pubkey_eq(k, t)), bad)?;

    // T7: the Phoenix signer slot holds phx_authority.
    let wallet = match rule.wallet {
        TraderWalletSlot::At(i) => i,
        TraderWalletSlot::NMinus3 => {
            let last = n.checked_sub(1).ok_or(bad)?;
            ensure(key_at(p, last) == Some(&SYSTEM_PROGRAM_ID), bad)?;
            n.checked_sub(3).ok_or(bad)?
        }
    };
    ensure(key_at(p, wallet).is_some_and(|k| pubkey_eq(k, a)), bad)?;

    // T8: phx_authority and T each exactly once in `P`.
    let (mut seen_a, mut seen_t) = (0usize, 0usize);
    for x in p {
        if pubkey_eq(x.key(), a) {
            seen_a = seen_a.saturating_add(1);
        }
        if pubkey_eq(x.key(), t) {
            seen_t = seen_t.saturating_add(1);
        }
    }
    ensure(seen_a == 1 && seen_t == 1, bad)?;

    // T9, T10.
    let forbidden_keys: [&Pubkey; 6] = [
        cfg.fee_inbox(),
        cfg.swap_authority(),
        cfg.buyback_authority(),
        cfg.rent_payer(),
        cfg.creator_escrow(),
        cfg.bb_unwrap(),
    ];
    for (i, x) in p.iter().enumerate() {
        let k = x.key();
        let owner_bad =
            x.is_owned_by(&SPL_TOKEN_PROGRAM_ID) || x.is_owned_by(&TOKEN_2022_PROGRAM_ID) || x.is_owned_by(program_id);
        let key_bad = forbidden_keys.iter().any(|f| pubkey_eq(f, k));
        ensure(!owner_bad && !key_bad, SijkaError::ForbiddenTradeAccount)?;
        let exec_ok = !x.executable() || i == 0 || pubkey_eq(k, &SYSTEM_PROGRAM_ID);
        ensure(exec_ok, SijkaError::ForbiddenTradeAccount)?;
    }
    Ok(TradePlan { rule, wallet })
}

/// T11: metas and account infos of the CPI. Every `P[i]` keeps the writable
/// and signer flags of the outer instruction, except `P[wallet]`
/// (`phx_authority`), which is always a read-only signer. Returns `n`.
pub fn fill_trade_metas<'a>(
    p: &'a [AccountInfo],
    wallet: usize,
    metas: &mut [AccountMeta<'a>; MAX_TRADE_ACCOUNTS],
    infos: &mut [&'a AccountInfo; MAX_TRADE_ACCOUNTS],
) -> usize {
    let mut n = 0usize;
    for (i, ((x, m), info)) in p.iter().zip(metas.iter_mut()).zip(infos.iter_mut()).enumerate() {
        *m = if i == wallet {
            AccountMeta::readonly_signer(x.key())
        } else {
            AccountMeta::new(x.key(), x.is_writable(), x.is_signer())
        };
        *info = x;
        n = i.saturating_add(1);
    }
    n
}

/// Tag 10 `trade` (SPEC §5.2).
#[inline(never)]
pub fn trade(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&TRADE, accounts, data)?;
    // T0: not a CPI.
    require_top_level()?;
    let [trader, config, phx_authority, p @ ..] = accounts else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };

    // Standard config check; tag 10 never writes state and takes no write
    // lock on `Config` (T12). The borrow ends with this block, before the CPI.
    let (plan, bump) = {
        let cfg_ref = load_config(config, program_id)?;
        expect_readonly(config)?;
        let cfg = config_view(&cfg_ref)?;
        let plan = check_trade(program_id, &cfg, trader, phx_authority, p, data).map_err(SijkaError::fail)?;
        (plan, cfg.phx_authority_bump())
    };

    // T11.
    let first = p.first().ok_or_else(|| SijkaError::InvalidTradeAccounts.fail())?;
    let mut metas: [AccountMeta; MAX_TRADE_ACCOUNTS] =
        [const { AccountMeta::readonly(&PHOENIX_PROGRAM_ID) }; MAX_TRADE_ACCOUNTS];
    let mut infos: [&AccountInfo; MAX_TRADE_ACCOUNTS] = [first; MAX_TRADE_ACCOUNTS];
    let n = fill_trade_metas(p, plan.wallet, &mut metas, &mut infos);
    let (Some(metas), Some(infos), Some(phx_data)) = (metas.get(..n), infos.get(..n), data.get(1..)) else {
        return Err(SijkaError::InvalidTradeAccounts.fail());
    };
    let ix = Instruction { program_id: &PHOENIX_PROGRAM_ID, accounts: metas, data: phx_data };
    let pda = PdaSeeds::new(SEED_PHX_AUTHORITY, bump);
    let seeds = pda.seeds();
    let signer = [Signer::from(&seeds)];
    cpi_signed(&ix, infos, &signer)
    // T12: nothing after the CPI.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        ATA_PROGRAM_ID, BPF_LOADER_UPGRADEABLE_ID, CONFIG_LEN, DISC_CONFIG, TRADE_ALLOWLIST, TRADER_ACCOUNT_LEN,
    };
    use crate::state::config::ConfigMut;
    use crate::util::test_utils::TestAccount;
    use phoenix_rise::ix::discriminants::PhoenixInstruction;
    use sha2::{Digest, Sha256};

    const PROGRAM: Pubkey = [0x11; 32];
    const TRADER: Pubkey = [0x7E; 32];
    const ADMIN: Pubkey = [0xAD; 32];
    const PHX: Pubkey = [0xA1; 32];
    const T: Pubkey = [0x7A; 32];
    /// Another trader account where `phx_authority` is the authority, e.g.
    /// `(A, 0, 1)` registered by a stranger with prefs 0 (TT-4).
    const SUB: Pubkey = [0x7B; 32];
    const FEE_INBOX: Pubkey = [0xF1; 32];
    const SWAP: Pubkey = [0xF2; 32];
    const BUYBACK: Pubkey = [0xF3; 32];
    const RENT: Pubkey = [0xF4; 32];
    const ESCROW: Pubkey = [0xF5; 32];
    const UNWRAP: Pubkey = [0xF6; 32];
    const NATIVE_LOADER: Pubkey = [0x0E; 32];
    const FLIGHT: Pubkey = [0xF7; 32];
    const BUMP: u8 = 253;

    fn cfg_with(f: impl FnOnce(&mut ConfigMut<'_>)) -> Vec<u8> {
        let mut b = vec![0u8; CONFIG_LEN];
        {
            let mut m = ConfigMut::new(&mut b).unwrap();
            m.set_discriminator(&DISC_CONFIG);
            m.set_version(1);
            m.set_admin(&ADMIN);
            m.set_trader(&TRADER);
            m.set_phoenix_trader(&T);
            m.set_phx_authority(&PHX);
            m.set_phx_authority_bump(BUMP);
            m.set_fee_inbox(&FEE_INBOX);
            m.set_swap_authority(&SWAP);
            m.set_buyback_authority(&BUYBACK);
            m.set_rent_payer(&RENT);
            m.set_creator_escrow(&ESCROW);
            m.set_bb_unwrap(&UNWRAP);
            f(&mut m);
        }
        b
    }

    fn cfg() -> Vec<u8> {
        cfg_with(|_| {})
    }

    #[derive(Clone, Debug)]
    struct Acc {
        key: Pubkey,
        owner: Pubkey,
        data: Vec<u8>,
        signer: bool,
        writable: bool,
        exec: bool,
    }

    impl Acc {
        fn new(key: Pubkey, owner: Pubkey) -> Self {
            Self { key, owner, data: vec![], signer: false, writable: false, exec: false }
        }
        fn w(mut self) -> Self {
            self.writable = true;
            self
        }
        fn s(mut self) -> Self {
            self.signer = true;
            self
        }
        fn x(mut self) -> Self {
            self.exec = true;
            self
        }
        fn build(&self) -> TestAccount {
            TestAccount::new(self.key, self.owner, 1_000_000, &self.data, self.signer, self.writable, self.exec)
        }
    }

    fn trader_acc() -> Acc {
        Acc::new(TRADER, SYSTEM_PROGRAM_ID).s().w()
    }
    fn config_acc(d: Vec<u8>) -> Acc {
        let mut a = Acc::new([0xC0; 32], PROGRAM);
        a.data = d;
        a
    }
    fn phx_acc() -> Acc {
        Acc::new(PHX, SYSTEM_PROGRAM_ID)
    }
    fn phoenix_program() -> Acc {
        Acc::new(PHOENIX_PROGRAM_ID, BPF_LOADER_UPGRADEABLE_ID).x()
    }
    fn system_program() -> Acc {
        Acc::new(SYSTEM_PROGRAM_ID, NATIVE_LOADER).x()
    }
    /// A Phoenix-owned market account (orderbook, spline, PAM, arena, PDA).
    fn market(i: usize) -> Acc {
        let mut k = [0xB0u8; 32];
        k[1] = u8::try_from(i).unwrap();
        Acc::new(k, PHOENIX_PROGRAM_ID).w()
    }
    fn our_trader() -> Acc {
        let mut a = Acc::new(T, PHOENIX_PROGRAM_ID).w();
        a.data = vec![0u8; TRADER_ACCOUNT_LEN];
        a
    }

    /// Payer / funder and System-program slots of the entries at `g = a = 1`
    /// (SPEC §5.2.1, appendix H §2), besides the fixed `TR` and `AU`.
    fn extra_slots(ix: PhoenixInstruction, n: usize) -> (Option<usize>, Option<usize>) {
        use PhoenixInstruction as I;
        match ix {
            I::PlaceLimitOrderWithConditionals => (Some(10), Some(12)),
            I::PlaceStopLoss | I::PlacePositionConditionalOrder => (Some(3), n.checked_sub(1)),
            I::PlaceAttachedConditionalOrder => (Some(7), Some(10)),
            I::CancelStopLoss => (Some(3), Some(7)),
            _ => (None, None),
        }
    }

    fn rule_of(ix: PhoenixInstruction) -> AllowedTrade {
        *allowed_trade(ix.tag()).unwrap()
    }

    fn wallet_of(r: &AllowedTrade, n: usize) -> usize {
        match r.wallet {
            TraderWalletSlot::At(i) => i,
            TraderWalletSlot::NMinus3 => n - 3,
        }
    }

    /// `P` of a well-formed `ix` with `n` accounts (extra accounts at the end
    /// are market accounts, which Phoenix ignores).
    fn phoenix_accounts(ix: PhoenixInstruction, n: usize) -> Vec<Acc> {
        let r = rule_of(ix);
        let mut p: Vec<Acc> = (0..n).map(market).collect();
        let mut put = |i: usize, a: Acc| {
            if i < n {
                p[i] = a;
            }
        };
        put(0, phoenix_program());
        put(1, Acc::new(PHOENIX_LOG_AUTHORITY, SYSTEM_PROGRAM_ID));
        put(2, Acc::new(PHOENIX_GLOBAL_CONFIG, PHOENIX_PROGRAM_ID).w());
        let (payer, system) = extra_slots(ix, n);
        if let Some(i) = payer {
            put(i, trader_acc());
        }
        if let Some(i) = system {
            put(i, system_program());
        }
        put(r.trader, our_trader());
        if n >= 3 {
            put(wallet_of(&r, n), phx_acc());
        }
        p
    }

    fn data_for(disc: u64, payload: usize) -> Vec<u8> {
        let mut d = vec![10u8];
        d.extend_from_slice(&disc.to_le_bytes());
        d.extend((0..payload).map(|i| u8::try_from(i % 251).unwrap()));
        d
    }

    fn accounts(cfg: Vec<u8>, p: Vec<Acc>) -> Vec<Acc> {
        let mut v = vec![trader_acc(), config_acc(cfg), phx_acc()];
        v.extend(p);
        v
    }

    fn run(accs: &[Acc], data: &[u8]) -> ProgramResult {
        let t: Vec<TestAccount> = accs.iter().map(Acc::build).collect();
        let infos: Vec<AccountInfo> = t.iter().map(TestAccount::info).collect();
        trade(&PROGRAM, &infos, data)
    }

    fn err(e: SijkaError) -> ProgramResult {
        Err(e.into())
    }

    /// A valid `PlaceLimitOrder` (n = 10).
    fn limit() -> (Vec<Acc>, Vec<u8>) {
        let ix = PhoenixInstruction::PlaceLimitOrder;
        (accounts(cfg(), phoenix_accounts(ix, 10)), data_for(ix.tag(), 40))
    }

    fn hex8(h: &str) -> [u8; 8] {
        let v: Vec<u8> = (0..8).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect();
        v.try_into().unwrap()
    }

    fn sha_disc(snake: &str) -> [u8; 8] {
        let h = Sha256::digest(format!("global:{snake}").as_bytes());
        h[..8].try_into().unwrap()
    }

    // ------------------------------------------------ one test per allowed ----

    /// Every rule for one allowlisted instruction (TU-T1): passes at `MIN`
    /// and at 27 accounts with any payload; `n` out of range, the trader or
    /// signer slot moved, duplicated or missing, `P[n − 1]` not System (for
    /// `n − 3` signers) all fail with `InvalidTradeAccounts`; the CPI metas
    /// keep the outer flags and make only `phx_authority` a read-only signer.
    fn check_allowed(ix: PhoenixInstruction, spec_hex: &str) {
        let r = rule_of(ix);
        assert_eq!(r.disc.to_le_bytes(), hex8(spec_hex), "{ix}: SPEC §5.2.1 hex");
        assert_eq!(r.disc.to_le_bytes(), sha_disc(ix.snake_case_instruction_name()), "{ix}: preimage");
        let bad = err(SijkaError::InvalidTradeAccounts);
        let min = r.min_accounts;

        for (n, payload) in [(min, 0usize), (min, 300), (MAX_TRADE_ACCOUNTS, 17)] {
            let a = accounts(cfg(), phoenix_accounts(ix, n));
            assert_eq!(run(&a, &data_for(ix.tag(), payload)), Ok(()), "{ix}: n = {n}, payload {payload}");
        }
        let d = data_for(ix.tag(), 8);
        // T4.
        assert_eq!(run(&accounts(cfg(), phoenix_accounts(ix, min - 1)), &d), bad, "{ix}: n = MIN - 1");
        let mut long = phoenix_accounts(ix, MAX_TRADE_ACCOUNTS);
        long.push(market(40));
        assert_eq!(run(&accounts(cfg(), long), &d), bad, "{ix}: n = 28");

        let n = min;
        let w = wallet_of(&r, n);
        // T6: another trader account of ours, or T moved elsewhere.
        let mut p = phoenix_accounts(ix, n);
        p[r.trader].key = SUB;
        assert_eq!(run(&accounts(cfg(), p), &d), bad, "{ix}: sub-account in TR");
        let tail_slot = match r.wallet {
            // n + 1 accounts: n - 2 is the signer, n the System program.
            TraderWalletSlot::NMinus3 => n - 3,
            TraderWalletSlot::At(_) => n,
        };
        let mut p = phoenix_accounts(ix, n + 1);
        p[r.trader] = market(30);
        p[tail_slot] = our_trader();
        assert_eq!(run(&accounts(cfg(), p), &d), bad, "{ix}: T only in the tail");
        // T7: signer slot holds another key; phx_authority moved to a payer slot.
        let mut p = phoenix_accounts(ix, n);
        p[w] = market(31);
        assert_eq!(run(&accounts(cfg(), p), &d), bad, "{ix}: AU is not phx_authority");
        if let (Some(payer), _) = extra_slots(ix, n) {
            let mut p = phoenix_accounts(ix, n);
            p[w] = trader_acc();
            p[payer] = phx_acc();
            assert_eq!(run(&accounts(cfg(), p), &d), bad, "{ix}: phx_authority in the payer slot");
        }
        if matches!(r.wallet, TraderWalletSlot::NMinus3) {
            let mut p = phoenix_accounts(ix, n);
            p[n - 1] = market(32);
            assert_eq!(run(&accounts(cfg(), p), &d), bad, "{ix}: P[n - 1] is not System");
            // Extra accounts shift the signer slot: phx_authority at the old
            // n - 3 and a stranger at the new one.
            let mut p = phoenix_accounts(ix, n + 1);
            p[n - 3] = phx_acc();
            p[n - 2] = market(33);
            assert_eq!(run(&accounts(cfg(), p), &d), bad, "{ix}: shifted tail");
        }
        // T8: phx_authority or T twice, or phx_authority missing.
        let mut p = phoenix_accounts(ix, n + 1);
        assert_eq!(run(&accounts(cfg(), p.clone()), &d), Ok(()), "{ix}: n + 1");
        p[tail_slot] = phx_acc();
        assert_eq!(run(&accounts(cfg(), p), &d), bad, "{ix}: phx_authority twice");
        let mut p = phoenix_accounts(ix, n + 1);
        p[tail_slot] = our_trader();
        assert_eq!(run(&accounts(cfg(), p), &d), bad, "{ix}: T twice");

        // T11: flags of the CPI metas.
        let mut outer = phoenix_accounts(ix, n);
        outer[w].writable = true; // writable outside: still read-only in the CPI
        let t: Vec<TestAccount> = outer.iter().map(Acc::build).collect();
        let infos: Vec<AccountInfo> = t.iter().map(TestAccount::info).collect();
        let mut metas = [const { AccountMeta::readonly(&PHOENIX_PROGRAM_ID) }; MAX_TRADE_ACCOUNTS];
        let mut refs: [&AccountInfo; MAX_TRADE_ACCOUNTS] = [&infos[0]; MAX_TRADE_ACCOUNTS];
        assert_eq!(fill_trade_metas(&infos, w, &mut metas, &mut refs), n);
        for (i, (m, a)) in metas.iter().zip(&outer).enumerate().take(n) {
            assert_eq!(m.pubkey, &a.key, "{ix}: meta {i} key");
            assert_eq!(refs[i].key(), &a.key, "{ix}: info {i}");
            if i == w {
                assert!(m.is_signer && !m.is_writable, "{ix}: phx_authority is a read-only signer");
            } else {
                assert_eq!((m.is_writable, m.is_signer), (a.writable, a.signer), "{ix}: meta {i} flags");
            }
        }
        // ... and the handler accepts a writable phx_authority (TT-9).
        let mut a = accounts(cfg(), outer);
        a[2].writable = true;
        assert_eq!(run(&a, &d), Ok(()), "{ix}: writable phx_authority outside");
    }

    macro_rules! allowed_tests {
        ($($t:ident: $ix:ident $hex:literal;)*) => {
            $(
                #[test]
                fn $t() {
                    check_allowed(PhoenixInstruction::$ix, $hex);
                }
            )*

            /// The 14 per-instruction tests cover exactly `TRADE_ALLOWLIST`.
            const ALLOWED_NAMES: &[&str] = &[$(stringify!($ix)),*];
        };
    }

    allowed_tests! {
        allowed_place_market_order: PlaceMarketOrder "5a76c0fcc0632791";
        allowed_place_limit_order: PlaceLimitOrder "6cb021ba92e501c5";
        allowed_place_multi_limit_order: PlaceMultiLimitOrder "ecd0ddac8de28154";
        allowed_place_multi_limit_order_v2: PlaceMultiLimitOrderV2 "406f28d202b126b2";
        allowed_cancel_orders_by_id: CancelOrdersById "eacc7e5ede168d18";
        allowed_cancel_up_to: CancelUpTo "1ad1f4fd3bafe336";
        allowed_cancel_all: CancelAll "62bf4bdc732847ed";
        allowed_cancel_all_plus_conditional: CancelAllPlusConditional "8eadee7e4f133567";
        allowed_place_limit_order_with_conditionals: PlaceLimitOrderWithConditionals "5f2d44a8e8dad25c";
        allowed_place_stop_loss: PlaceStopLoss "ec2ea442eb5ca289";
        allowed_place_position_conditional_order: PlacePositionConditionalOrder "416c53814cc15c8f";
        allowed_place_attached_conditional_order: PlaceAttachedConditionalOrder "2b7588804896657a";
        allowed_cancel_conditional_order: CancelConditionalOrder "52681933f83642b8";
        allowed_cancel_stop_loss: CancelStopLoss "78c90a660c096f7e";
    }

    // ---------------------------------------------- one test per forbidden ----

    /// A forbidden discriminator (TU-T1, TT-2): with a layout that would pass
    /// for `PlaceLimitOrder`, and with the layout of every allowed entry, the
    /// instruction is `TradeInstructionNotAllowed`.
    fn check_forbidden(name: &str, derived: [u8; 8], spec_hex: &str) {
        assert_eq!(derived, hex8(spec_hex), "{name}: appendix H §1 hex");
        let disc = u64::from_le_bytes(derived);
        assert!(allowed_trade(disc).is_none(), "{name} must not be allowlisted");
        let not_allowed = err(SijkaError::TradeInstructionNotAllowed);
        for payload in [0usize, 64] {
            let (a, _) = limit();
            assert_eq!(run(&a, &data_for(disc, payload)), not_allowed, "{name}: payload {payload}");
        }
        for r in TRADE_ALLOWLIST {
            let ix = PhoenixInstruction::from_tag(r.disc).unwrap();
            let a = accounts(cfg(), phoenix_accounts(ix, r.min_accounts));
            assert_eq!(run(&a, &data_for(disc, 16)), not_allowed, "{name} in the layout of {ix}");
        }
    }

    macro_rules! forbidden_tests {
        (@disc sdk $name:ident) => { PhoenixInstruction::$name.discriminant() };
        (@disc idl $name:ident $snake:literal) => { sha_disc($snake) };
        ($($t:ident: $kind:ident $name:ident $(($snake:literal))? $hex:literal;)*) => {
            $(
                #[test]
                fn $t() {
                    check_forbidden(stringify!($name), forbidden_tests!(@disc $kind $name $($snake)?), $hex);
                }
            )*

            /// The 99 per-instruction tests (appendix H §1, classes other than "ДА").
            const FORBIDDEN_NAMES: &[&str] = &[$(stringify!($name)),*];
        };
    }

    // Generated from appendix H §1 (rows 15–113): `sdk` names are in the
    // `PhoenixInstruction` enum of SDK 0.6.5; `idl` names exist only in the
    // on-chain IDL and are derived from `sha256("global:<snake>")`.
    forbidden_tests! {
        forbidden_place_market_order_delegated: sdk PlaceMarketOrderDelegated "a02315eb6eb6f541";
        forbidden_create_conditional_orders_account: sdk CreateConditionalOrdersAccount "c906703de70f39f8";
        forbidden_acknowledge_restart: sdk AcknowledgeRestart "d338ec61846a369c";
        forbidden_clear_expired_orders: sdk ClearExpiredOrders "805f66a992cdf85e";
        forbidden_clear_position_flip_orders: idl ClearPositionFlipOrders ("clear_position_flip_orders") "f57125625234785b";
        forbidden_migrate_trader_state: idl MigrateTraderState ("migrate_trader_state") "160e4ad66c48cf64";
        forbidden_sync_native: sdk SyncNative "9bdb2424ef801541";
        forbidden_uncross_crank: sdk UncrossCrank "c4795efd8b2afc93";
        forbidden_update_trader_state: sdk UpdateTraderState "f98b522c7e4285dc";
        forbidden_execute_conditional_orders: sdk ExecuteConditionalOrders "65d66e00bee2b1ec";
        forbidden_execute_stop_loss: sdk ExecuteStopLoss "267a5a5ab6f10704";
        forbidden_ping_conditional_orders: sdk PingConditionalOrders "87aaa622d0e65b40";
        forbidden_update_spline_parameters: sdk UpdateSplineParameters "f15b8baa1229cb16";
        forbidden_update_spline_position_limits_config: sdk UpdateSplinePositionLimitsConfig "603c057013900d6b";
        forbidden_update_spline_price: sdk UpdateSplinePrice "2d9bc83425d6bb8c";
        forbidden_accept_escrow_request: sdk AcceptEscrowRequest "b6293ee3e4af1689";
        forbidden_authorized_transfer_collateral: sdk AuthorizedTransferCollateral "ded6450f74737925";
        forbidden_cancel_escrow_request: sdk CancelEscrowRequest "ca1aa3ef20085502";
        forbidden_claim_fees: sdk ClaimFees "52fbe99c0c34b8ca";
        forbidden_close_matched_positions: sdk CloseMatchedPositions "70ae20785d710aa1";
        forbidden_consume_withdraw_queue: sdk ConsumeWithdrawQueue "e428d38b27d47471";
        forbidden_create_escrow_account: sdk CreateEscrowAccount "9293e12f33407001";
        forbidden_create_escrow_request: sdk CreateEscrowRequest "74a4ecccbb84c3db";
        forbidden_deposit_funds: sdk DepositFunds "ca2734d33514fa58";
        forbidden_liquidate_native_sol: sdk LiquidateNativeSol "ad2cd10a68fa4032";
        forbidden_liquidate_via_market_order: sdk LiquidateViaMarketOrder "fbf1b86c46467fc6";
        forbidden_liquidation_transfer: sdk LiquidationTransfer "39dad744ae17cc7f";
        forbidden_settle_closed_market_position: sdk SettleClosedMarketPosition "1bdedde9880ffed2";
        forbidden_swap_native: sdk SwapNative "5893b1ba81eaefe7";
        forbidden_transfer_collateral: sdk TransferCollateral "9da33f1bf248fb61";
        forbidden_transfer_collateral_child_to_parent: sdk TransferCollateralChildToParent "3364b1738b87f78b";
        forbidden_transfer_native_sol: sdk TransferNativeSol "cc41d9ce38b44afc";
        forbidden_transfer_native_sol_from_child_to_parent: sdk TransferNativeSolFromChildToParent "5aaf316a367308b9";
        forbidden_upsert_escrow_request: sdk UpsertEscrowRequest "d538565d2267a063";
        forbidden_withdraw_funds: sdk WithdrawFunds "f1241d6fd01f68d9";
        forbidden_withdraw_funds_with_fee: sdk WithdrawFundsWithFee "ca5e5e2a9be35861";
        forbidden_withdraw_native_sol: sdk WithdrawNativeSol "c968bb6950cc548a";
        forbidden_close_trader_account: sdk CloseTraderAccount "7ede2695cfa46cbb";
        forbidden_realloc_trader: sdk ReallocTrader "aef83f23e1ec13cc";
        forbidden_register_trader: sdk RegisterTrader "4bf3e0a701053320";
        forbidden_sync_parent_to_child: sdk SyncParentToChild "af89d90beb279613";
        forbidden_create_permission: sdk CreatePermission "beb61aa49cdd0800";
        forbidden_delegate_trader: sdk DelegateTrader "03a4c06a775b7ae0";
        forbidden_revoke_permission: sdk RevokePermission "745221b57990f9e3";
        forbidden_set_permission: sdk SetPermission "467e29c2f5bd8008";
        forbidden_set_permission_delegated: sdk SetPermissionDelegated "23193944ff1aa1e5";
        forbidden_set_trader_capabilities_delegated: sdk SetTraderCapabilitiesDelegated "cfaa111535235897";
        forbidden_set_trader_capability: sdk SetTraderCapability "bf482dbed6fab6d5";
        forbidden_set_trader_cap_override: idl SetTraderCapOverride ("set_trader_cap_override") "bf93afb9c064e95e";
        forbidden_update_trader_fees: sdk UpdateTraderFees "b6e939cdaea849ed";
        forbidden_activate_native_sol: idl ActivateNativeSol ("activate_native_sol") "0ff65b5d46e9bf78";
        forbidden_add_market: sdk AddMarket "2989b97e458bfe37";
        forbidden_authorized_force_cancel: sdk AuthorizedForceCancel "0d16ddead3a5ac02";
        forbidden_authorized_force_cancel_by_id: sdk AuthorizedForceCancelById "7a9f0c9f906ce1f1";
        forbidden_change_exchange_status: sdk ChangeExchangeStatus "d466c8768aa2e4a5";
        forbidden_change_market_status: sdk ChangeMarketStatus "dd7fe029b1917e08";
        forbidden_change_spot_asset_params: idl ChangeSpotAssetParams ("change_spot_asset_params") "296ece48bbc5c570";
        forbidden_claim_authority: sdk ClaimAuthority "de84b97b7f6b061f";
        forbidden_close_market: sdk CloseMarket "589af8ba300e7bf4";
        forbidden_configure_native_sol: idl ConfigureNativeSol ("configure_native_sol") "f1132c257733c51b";
        forbidden_deactivate_spline: sdk DeactivateSpline "00fe1664eec576b5";
        forbidden_delete_tombstoned_market: sdk DeleteTombstonedMarket "9211fc74de713466";
        forbidden_enable_feature: sdk EnableFeature "1b17ceffbe13e75c";
        forbidden_force_cancel_after_hours: sdk ForceCancelAfterHours "930de03df8ea40a4";
        forbidden_force_cancel_all: sdk ForceCancelAll "c900bc7f29375030";
        forbidden_force_cancel_risk_increasing: sdk ForceCancelRiskIncreasing "2937d9235c482aee";
        forbidden_force_cancel_stop_loss: sdk ForceCancelStopLoss "72e673aa424f13ac";
        forbidden_initialize_arena: sdk InitializeArena "0b25dd01cd7819e6";
        forbidden_market_closed_force_cancel_all: sdk MarketClosedForceCancelAll "e5658ff996afafdb";
        forbidden_name_successor: sdk NameSuccessor "a0cb25e5e17781ec";
        forbidden_rebirth: sdk Rebirth "8ff19a4f74e2ff90";
        forbidden_register_spline: sdk RegisterSpline "1eb0a04ffc75f13a";
        forbidden_remove_all_oracles: sdk RemoveAllOracles "a4405bd289bd8726";
        forbidden_remove_empty_arena: sdk RemoveEmptyArena "9b41a24fd3ddc5a8";
        forbidden_remove_oracle: sdk RemoveOracle "3c5d33c5b62aaa1a";
        forbidden_set_multi_arena_additional_nodes_watermark: sdk SetMultiArenaAdditionalNodesWatermark "ecfcded01f839d93";
        forbidden_set_multi_arena_num_nodes_per_arena: sdk SetMultiArenaNumNodesPerArena "5bb4f1c04e84fc83";
        forbidden_set_spot_asset_price: idl SetSpotAssetPrice ("set_spot_asset_price") "f6ace619be3a3a09";
        forbidden_tombstone_market: sdk TombstoneMarket "5ab11158550bb160";
        forbidden_update_authorities: sdk UpdateAuthorities "afe48912af46dca5";
        forbidden_update_commodity_market_state: sdk UpdateCommodityMarketState "2df561b8c8938e49";
        forbidden_update_funding_parameters: sdk UpdateFundingParameters "65c368687414dfbc";
        forbidden_update_market_fees: sdk UpdateMarketFees "bb2479ab8313f375";
        forbidden_update_oracle_prices_with_ordering: sdk UpdateOraclePricesWithOrdering "a4000efa3ac61918";
        forbidden_update_perp_cancel_risk_factor: sdk UpdatePerpCancelRiskFactor "5806b9cd761c81f2";
        forbidden_update_perp_isolated_only: sdk UpdatePerpIsolatedOnly "6538a3fa4923735b";
        forbidden_update_perp_leverage_tiers: sdk UpdatePerpLeverageTiers "6edff46322536179";
        forbidden_update_perp_mark_price_parameters: sdk UpdatePerpMarkPriceParameters "fe560d5e2be0a0e2";
        forbidden_update_perp_max_liquidation_size: sdk UpdatePerpMaxLiquidationSize "dd3f02c72cf17cde";
        forbidden_update_perp_open_interest_cap: sdk UpdatePerpOpenInterestCap "4b897405507b6bb1";
        forbidden_update_perp_parameters_delegated: idl UpdatePerpParametersDelegated ("update_perp_parameters_delegated") "f5b934e4b5588ede";
        forbidden_update_perp_risk_factors: idl UpdatePerpRiskFactors ("update_perp_risk_factors") "08f2d1cc4f911825";
        forbidden_update_perp_transfer_fee_tiers: idl UpdatePerpTransferFeeTiers ("update_perp_transfer_fee_tiers") "aaf6b7c173bd975e";
        forbidden_update_perp_u_pnl_risk_factor: sdk UpdatePerpUPnlRiskFactor "71d6e2fe93095edc";
        forbidden_update_perp_u_pnl_risk_factor_for_withdrawals: sdk UpdatePerpUPnlRiskFactorForWithdrawals "fc200a58eef5683b";
        forbidden_update_withdraw_parameters: sdk UpdateWithdrawParameters "57d1e1845b97f984";
        forbidden_update_withdraw_rate_limits: sdk UpdateWithdrawRateLimits "bbf692b68dd82401";
        forbidden_log: sdk Log "8de6d6f209d1cfaa";
        forbidden_log_event_lengths: sdk LogEventLengths "f70786cbb5479947";
    }

    /// The per-instruction tests cover all 113 instructions of the on-chain
    /// IDL: the 14 allowed ones are exactly `TRADE_ALLOWLIST`, and every
    /// variant of the SDK enum is in one of the two tables.
    #[test]
    fn tables_cover_every_phoenix_instruction() {
        assert_eq!(ALLOWED_NAMES.len(), 14);
        assert_eq!(FORBIDDEN_NAMES.len(), 99);
        let allowed: Vec<u64> =
            ALLOWED_NAMES.iter().map(|n| PhoenixInstruction::from_instruction_name(n).unwrap().tag()).collect();
        let mut want: Vec<u64> = TRADE_ALLOWLIST.iter().map(|r| r.disc).collect();
        let mut got = allowed.clone();
        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(got, want);
        for ix in PhoenixInstruction::ALL {
            let name = ix.instruction_name();
            let a = ALLOWED_NAMES.contains(&name);
            let f = FORBIDDEN_NAMES.contains(&name);
            assert!(a ^ f, "{name}: exactly one table");
        }
        assert_eq!(PhoenixInstruction::ALL.len(), 103);
        let mut all: Vec<&str> = ALLOWED_NAMES.iter().chain(FORBIDDEN_NAMES).copied().collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 113);
    }

    // ------------------------------------------------------- other rules ----

    #[test]
    fn shape_and_config() {
        let (a, d) = limit();
        // Fewer than the three fixed accounts.
        assert_eq!(run(&a[..2], &d), err(SijkaError::InvalidAccountCount));
        assert_eq!(run(&[], &d), err(SijkaError::InvalidAccountCount));
        // Config: owner, length, discriminator; must be read-only.
        let mut x = a.clone();
        x[1].owner = [9; 32];
        assert_eq!(run(&x, &d), err(SijkaError::InvalidConfigAccount));
        let mut x = a.clone();
        x[1].data[0] ^= 1;
        assert_eq!(run(&x, &d), err(SijkaError::InvalidConfigAccount));
        let mut x = a.clone();
        x[1].data.pop();
        assert_eq!(run(&x, &d), err(SijkaError::InvalidConfigAccount));
        let mut x = a.clone();
        x[1].writable = true;
        assert_eq!(run(&x, &d), err(SijkaError::AccountMustBeReadonly));
        assert_eq!(run(&a, &d), Ok(()));
    }

    #[test]
    fn t1_trading_key() {
        let (a, d) = limit();
        let unauthorized = err(SijkaError::UnauthorizedTrader);
        let mut x = a.clone();
        x[0].signer = false;
        assert_eq!(run(&x, &d), unauthorized, "not signed");
        let mut x = a.clone();
        x[0].key = ADMIN;
        assert_eq!(run(&x, &d), unauthorized, "admin is not the trading key");
        let mut x = a.clone();
        x[0].key = [0x55; 32];
        assert_eq!(run(&x, &d), unauthorized, "stranger");
        // set_trader(0): trading off, whoever signs.
        let mut x = a.clone();
        x[1] = config_acc(cfg_with(|m| m.set_trader(&[0; 32])));
        assert_eq!(run(&x, &d), unauthorized, "trader = 0");
        x[0].key = [0; 32];
        assert_eq!(run(&x, &d), unauthorized, "zero key cannot match zero trader");
        // T1 comes before everything else of §5.2.3.
        let mut x = a.clone();
        x[0].signer = false;
        x[2].key = [0x42; 32];
        assert_eq!(run(&x, &[10]), unauthorized);
    }

    #[test]
    fn t2_and_reference_slot() {
        let (a, d) = limit();
        let mut x = a.clone();
        x[1] = config_acc(cfg_with(|m| m.set_phoenix_trader(&[0; 32])));
        assert_eq!(run(&x, &d), err(SijkaError::TraderNotRegistered));
        let mut x = a.clone();
        x[2].key = [0x42; 32];
        assert_eq!(run(&x, &d), err(SijkaError::InvalidPda));
        // The reference slot's flags do not matter.
        let mut x = a.clone();
        x[2].writable = true;
        assert_eq!(run(&x, &d), Ok(()));
    }

    #[test]
    fn t3_short_data() {
        let (a, _) = limit();
        let tag = PhoenixInstruction::PlaceLimitOrder.tag().to_le_bytes();
        for len in 1..TRADE_FIXED_DATA {
            let mut d = vec![10u8];
            d.extend_from_slice(&tag[..len - 1]);
            assert_eq!(run(&a, &d), err(SijkaError::TradeInstructionNotAllowed), "len {len}");
        }
        // Unknown discriminators (not Phoenix at all).
        for disc in [0u64, u64::MAX, 1] {
            assert_eq!(run(&a, &data_for(disc, 8)), err(SijkaError::TradeInstructionNotAllowed));
        }
        // Data exactly 9 bytes is a valid PlaceLimitOrder shape for the program.
        assert_eq!(run(&a, &data_for(PhoenixInstruction::PlaceLimitOrder.tag(), 0)), Ok(()));
    }

    #[test]
    fn t5_program_and_header_slots() {
        let (a, d) = limit();
        let bad = err(SijkaError::InvalidTradeAccounts);
        for other in [FLIGHT, SPL_TOKEN_PROGRAM_ID, PROGRAM, SYSTEM_PROGRAM_ID, crate::constants::EMBER_PROGRAM_ID] {
            let mut x = a.clone();
            x[3].key = other;
            assert_eq!(run(&x, &d), bad, "P[0] = {other:?}");
        }
        for slot in [4usize, 5] {
            let mut x = a.clone();
            x[slot].key = [0x42; 32];
            assert_eq!(run(&x, &d), bad, "P[{}]", slot - 3);
        }
    }

    #[test]
    fn t9_forbidden_accounts_anywhere_in_p() {
        let (a, d) = limit();
        let forbidden = err(SijkaError::ForbiddenTradeAccount);
        let mut cases: Vec<Acc> = vec![
            // Our token accounts (vault_usdc, escrows, buyback) and any foreign one.
            Acc::new([0xE1; 32], SPL_TOKEN_PROGRAM_ID).w(),
            Acc::new([0xE2; 32], TOKEN_2022_PROGRAM_ID).w(),
            // Our state accounts (config, buyback_state).
            config_acc(cfg()),
            Acc::new([0xE3; 32], PROGRAM).w(),
        ];
        for k in [FEE_INBOX, SWAP, BUYBACK, RENT, ESCROW, UNWRAP] {
            cases.push(Acc::new(k, SYSTEM_PROGRAM_ID).w());
        }
        for c in cases {
            // In a Phoenix slot (the orderbook, P[8]) and in the tail.
            let mut x = a.clone();
            x[3 + 8] = c.clone();
            assert_eq!(run(&x, &d), forbidden, "{:?} in P[8]", c.key);
            let mut x = accounts(cfg(), phoenix_accounts(PhoenixInstruction::PlaceLimitOrder, 12));
            x[3 + 11] = c.clone();
            assert_eq!(run(&x, &d), forbidden, "{:?} in the tail", c.key);
        }
    }

    #[test]
    fn t10_executables() {
        let (_, d) = limit();
        let forbidden = err(SijkaError::ForbiddenTradeAccount);
        let base = || accounts(cfg(), phoenix_accounts(PhoenixInstruction::PlaceLimitOrder, 12));
        for (key, owner) in [
            (SPL_TOKEN_PROGRAM_ID, NATIVE_LOADER),
            (TOKEN_2022_PROGRAM_ID, BPF_LOADER_UPGRADEABLE_ID),
            (ATA_PROGRAM_ID, NATIVE_LOADER),
            (PROGRAM, BPF_LOADER_UPGRADEABLE_ID),
            (FLIGHT, BPF_LOADER_UPGRADEABLE_ID),
            (PHOENIX_PROGRAM_ID, BPF_LOADER_UPGRADEABLE_ID),
        ] {
            let mut x = base();
            x[3 + 11] = Acc::new(key, owner).x();
            assert_eq!(run(&x, &d), forbidden, "{key:?} in the tail");
        }
        // The System program is allowed anywhere.
        let mut x = base();
        x[3 + 11] = system_program();
        assert_eq!(run(&x, &d), Ok(()));
    }

    #[test]
    fn t8_runs_before_t9() {
        // SPEC §5.2.3: the order is normative.
        let mut x = accounts(cfg(), phoenix_accounts(PhoenixInstruction::PlaceLimitOrder, 12));
        x[3 + 10] = phx_acc();
        x[3 + 11] = Acc::new([0xE1; 32], SPL_TOKEN_PROGRAM_ID).w();
        let d = data_for(PhoenixInstruction::PlaceLimitOrder.tag(), 8);
        assert_eq!(run(&x, &d), err(SijkaError::InvalidTradeAccounts));
    }

    #[test]
    fn t13_no_mode_checks() {
        let (a, d) = limit();
        let modes = cfg_with(|m| {
            m.set_recovery_mode(1);
            m.set_admin(&[0; 32]);
            // Retired bytes (SPEC v4): the former `admin_renounced_ts@1000`
            // and `inflow_pause_mask@1152`, and a keeper key @48.
            m.bytes_mut()[1000] = 5;
            m.bytes_mut()[1152] = 3;
            m.set_keeper(&[0x4B; 32]);
        });
        let mut x = a.clone();
        x[1] = config_acc(modes);
        assert_eq!(run(&x, &d), Ok(()));
        // The retired pause byte @10 is ignored.
        let mut x = a.clone();
        x[1].data[10] = 2;
        assert_eq!(run(&x, &d), Ok(()));
    }

    #[test]
    fn trading_key_may_repeat_in_p() {
        // The trading key as payer / funder is allowed (SPEC §5.2.2 row 0).
        let ix = PhoenixInstruction::PlaceStopLoss;
        let a = accounts(cfg(), phoenix_accounts(ix, 13));
        assert!(a[3..].iter().any(|x| x.key == TRADER));
        assert_eq!(run(&a, &data_for(ix.tag(), 27)), Ok(()));
    }

    #[test]
    fn check_trade_reports_the_signer_slot() {
        let ix = PhoenixInstruction::PlacePositionConditionalOrder;
        let a = accounts(cfg(), phoenix_accounts(ix, 20));
        let t: Vec<TestAccount> = a.iter().map(Acc::build).collect();
        let infos: Vec<AccountInfo> = t.iter().map(TestAccount::info).collect();
        let c = cfg();
        let view = Config::new(&c).unwrap();
        let plan = check_trade(&PROGRAM, &view, &infos[0], &infos[2], &infos[3..], &data_for(ix.tag(), 3)).unwrap();
        assert_eq!(plan.wallet, 17);
        assert_eq!(plan.rule, rule_of(ix));
        // Errors of the pure check are not logged; the handler logs them.
        let e = check_trade(&PROGRAM, &view, &infos[0], &infos[2], &infos[3..], &[10]);
        assert_eq!(e, Err(SijkaError::TradeInstructionNotAllowed));
    }
}
