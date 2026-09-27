// Copyright (c) 2026 prt1sn. All rights reserved.
//! Setup and admin instructions, tags 0–3 and 28 (SPEC §5.1).
//!
//! Every handler starts with the SPEC §4 shape check (`check_shape`: exact
//! data length, then exact account count), then validates every account
//! (key / PDA, owner, signer, writable), then the admin (§5.0.4), then the
//! instruction data values, and only then reads the clock and writes state.
//! No handler moves funds. The CPIs here are Phoenix `RegisterTrader` (tag 2,
//! payer `rent_payer`) and the System call that creates `Config` (tag 0).
//! No instruction of the program ever calls Phoenix `DelegateTrader`: the
//! position authority of our trader stays `phx_authority` (SPEC v3, §5.1.9).
//!
//! Tag 3 `set_trader` sets the trading key, the only signer of tag 10
//! `trade` (SPEC §5.1.3, §5.2); tag 28 `set_keeper` sets the keeper key, the
//! only signer of the swaps 20, 43 and the buyback chunks 44, 45 (SPEC
//! §5.1.10). Tags 4–6 (admin pause,
//! market whitelist, trading limits) are retired (SPEC v2, DECISIONS §19),
//! tag 9 (the SPEC v2 delegate) with SPEC v3, tags 7 (`set_harvest_params`)
//! and 8 (`renounce_admin`) with SPEC v4 (DECISIONS §23): the admin exists for
//! good and the harvest parameters are fixed at `initialize`.
//!
//! Handlers are split into a thin public entry and an `*_at` body that takes
//! the clock as a function, so host tests can run the full logic with a fixed
//! time (on the host the runtime sysvars are unavailable). The clock is read
//! only after every check has passed.
//!
//! There are no admin parameter or pause instructions (tags 25, 26, 47, 48
//! retired with SPEC v4).

use phoenix_rise::cpi::{CpiScratch, phoenix};
use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::Signer;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::accounting::initial_last_harvest_ts;
use crate::constants::{
    ACCOUNT_VERSION, BPF_LOADER_UPGRADEABLE_ID, CONFIG_LEN, CREATOR_SHARE_BPS, DISC_CONFIG, DISC_EMBER_STATE,
    DISC_TRADER, EMBER_PROGRAM_ID, EMBER_STATE, GC_MIN_LEN, PHOENIX_LOG_AUTHORITY, PHOENIX_PROGRAM_ID,
    PUMP_FEES_PROGRAM, SEED_BB_UNWRAP, SEED_BUYBACK_AUTHORITY, SEED_BUYBACK_STATE, SEED_CONFIG, SEED_CREATOR_ESCROW,
    SEED_FEE_INBOX, SEED_PHOENIX_TRADER, SEED_PHX_AUTHORITY, SEED_PUMP_SHARING_CONFIG, SEED_RENT_PAYER,
    SEED_SWAP_AUTHORITY, SHARING_CONFIG_DISC, SPL_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
    TRADER_ACCOUNT_LEN, TRADER_MAX_POSITIONS, TRADER_PREFS, WSOL_MINT,
};
use crate::cpi::PdaSeeds;
use crate::cpi::system::create_pda_account;
use crate::cpi_tramp::{SCRATCH_REGISTER_ACCOUNTS, SCRATCH_REGISTER_DATA, phx_register};
use crate::error::SijkaError;
use crate::events::{EvInitialize, EvKeeperSet, EvTokenMintSet, EvTraderRegistered, EvTraderSet};
use crate::external::layout::{ember_state as eml, loader, mint as ml};
use crate::external::phoenix_accounts::{TraderHeader, check_global_config, trader_header};
use crate::external::pump_accounts::read_sharing_config;
use crate::instructions::{
    INITIALIZE, REGISTER_PHOENIX_TRADER, SET_KEEPER, SET_TOKEN_MINT, SET_TRADER, check_admin, check_shape,
};
use crate::state::config::harvest_params::HarvestParams;
use crate::state::config::inflow_params::InflowParams;
use crate::state::config::{Config, ConfigMut, config_view, config_view_mut, load_config_mut};
use crate::util::accounts::{expect_key, expect_owner, expect_program, expect_system_empty, expect_writable};
use crate::util::bytes::{array_ref, is_zero_key, read_key, read_u8, read_u16, read_u32};
use crate::util::math::{add_u64, rent_exempt_minimum};
use crate::util::pda;
use crate::util::runtime::clock;

// ------------------------------------------------------------- clock ----

/// The `Clock` fields the handlers use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    pub ts: i64,
    pub slot: u64,
}

/// Clock source. Handlers call it only after every check has passed.
pub type ClockFn = fn() -> Result<Now, ProgramError>;

fn runtime_now() -> Result<Now, ProgramError> {
    let c = clock()?;
    Ok(Now { ts: c.unix_timestamp, slot: c.slot })
}

// ------------------------------------------------------------ helpers ----

#[inline(always)]
fn bad_data() -> ProgramError {
    SijkaError::InvalidInstructionData.fail()
}

/// Instruction data readers (bounds-checked; the shape check already fixed
/// the length, so the error branch is dead on valid input).
fn data_u8(data: &[u8], off: usize) -> Result<u8, ProgramError> {
    read_u8(data, off).ok_or_else(bad_data)
}

fn data_array<const N: usize>(data: &[u8], off: usize) -> Result<&[u8; N], ProgramError> {
    array_ref::<N>(data, off).ok_or_else(bad_data)
}

/// Shorthand for the 32-byte `Pubkey` fields.
fn data_key(data: &[u8], off: usize) -> Result<&Pubkey, ProgramError> {
    read_key(data, off).ok_or_else(bad_data)
}

/// `creator_share_bps` as stored in `Config` (u16).
const CREATOR_SHARE_BPS_U16: u16 = 2000;
const _: () = assert!(CREATOR_SHARE_BPS_U16 as u64 == CREATOR_SHARE_BPS);

/// `Config.version` (u16) for layout version 1.
const CONFIG_VERSION: u16 = 1;
const _: () = assert!(CONFIG_VERSION as u64 == ACCOUNT_VERSION as u64);

/// The nine program PDAs as stored in `Config` (`config` itself is the
/// account's own key). Roles may not be any of them (SPEC §5.1.0 step 5,
/// §5.1.3 step 2).
fn stored_pdas<'a>(cfg: &Config<'a>, config_key: &'a Pubkey) -> [&'a Pubkey; 9] {
    [
        config_key,
        cfg.buyback_state(),
        cfg.bb_unwrap(),
        cfg.fee_inbox(),
        cfg.phx_authority(),
        cfg.swap_authority(),
        cfg.buyback_authority(),
        cfg.rent_payer(),
        cfg.creator_escrow(),
    ]
}

/// Step 3 of SPEC §5.0.4: stamp `last_admin_action_ts` on success.
#[inline(always)]
fn stamp_admin(cfg: &mut ConfigMut<'_>, now: &Now) {
    cfg.set_last_admin_action_ts(now.ts);
}

// ================================================================ tag 0 ====

/// One PDA of this program: key and canonical bump.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pda {
    pub key: Pubkey,
    pub bump: u8,
}

/// All PDAs of this program (SPEC §2.1), derived with `find_program_address`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProgramPdas {
    pub config: Pda,
    pub buyback_state: Pda,
    pub bb_unwrap: Pda,
    pub fee_inbox: Pda,
    pub phx_authority: Pda,
    pub swap_authority: Pda,
    pub buyback_authority: Pda,
    pub rent_payer: Pda,
    pub creator_escrow: Pda,
}

impl ProgramPdas {
    /// `find_program_address([seed], program_id)` for each of the nine PDAs.
    pub fn derive(program_id: &Pubkey) -> Result<Self, ProgramError> {
        let f = |seed: &[u8]| pda::find(&[seed], program_id).map(|(key, bump)| Pda { key, bump });
        Ok(Self {
            config: f(SEED_CONFIG)?,
            buyback_state: f(SEED_BUYBACK_STATE)?,
            bb_unwrap: f(SEED_BB_UNWRAP)?,
            fee_inbox: f(SEED_FEE_INBOX)?,
            phx_authority: f(SEED_PHX_AUTHORITY)?,
            swap_authority: f(SEED_SWAP_AUTHORITY)?,
            buyback_authority: f(SEED_BUYBACK_AUTHORITY)?,
            rent_payer: f(SEED_RENT_PAYER)?,
            creator_escrow: f(SEED_CREATOR_ESCROW)?,
        })
    }

    pub fn keys(&self) -> [&Pubkey; 9] {
        [
            &self.config.key,
            &self.buyback_state.key,
            &self.bb_unwrap.key,
            &self.fee_inbox.key,
            &self.phx_authority.key,
            &self.swap_authority.key,
            &self.buyback_authority.key,
            &self.rent_payer.key,
            &self.creator_escrow.key,
        ]
    }
}

/// `initialize` instruction data (SPEC §5.1.0), borrowed from the input.
#[derive(Clone, Copy)]
pub struct InitArgs<'a> {
    pub admin: &'a Pubkey,
    pub creator_payout: &'a Pubkey,
    pub quote_mint: &'a Pubkey,
    pub harvest_params: &'a [u8; 64],
    pub inflow_params: &'a [u8; 40],
}

/// Parse the 201-byte `initialize` data (length already checked).
pub fn parse_init_args(data: &[u8]) -> Result<InitArgs<'_>, ProgramError> {
    Ok(InitArgs {
        admin: data_key(data, 1)?,
        creator_payout: data_key(data, 33)?,
        quote_mint: data_key(data, 65)?,
        harvest_params: data_array::<64>(data, 97)?,
        inflow_params: data_array::<40>(data, 161)?,
    })
}

/// SPEC §5.1.0 steps 3, 5, 6: quote mint, roles, structural parameter checks.
pub fn check_init_args(a: &InitArgs<'_>, usdc_mint: &Pubkey, pdas: &ProgramPdas) -> Result<(), SijkaError> {
    if !pubkey_eq(a.quote_mint, &WSOL_MINT) && !pubkey_eq(a.quote_mint, usdc_mint) {
        return Err(SijkaError::InvalidQuoteMint);
    }
    if is_zero_key(a.admin) || is_zero_key(a.creator_payout) {
        return Err(SijkaError::InvalidParams);
    }
    let keys = pdas.keys();
    for role in [a.admin, a.creator_payout] {
        if keys.iter().any(|k| pubkey_eq(k, role)) {
            return Err(SijkaError::InvalidParams);
        }
    }
    HarvestParams::from_array(a.harvest_params).validate()?;
    InflowParams::from_array(a.inflow_params).validate()?;
    Ok(())
}

/// `program_data` contents (SPEC §5.1.0 #3): `ProgramData` state, upgrade
/// authority `Some(payer)`. A program without an upgrade authority, or with
/// another one, is `NotUpgradeAuthority`.
pub fn check_program_data(data: &[u8], payer: &Pubkey) -> Result<(), SijkaError> {
    if data.len() < loader::PD_METADATA_LEN || read_u32(data, loader::STATE_TAG) != Some(loader::TAG_PROGRAM_DATA) {
        return Err(SijkaError::InvalidExternalAccount);
    }
    if read_u8(data, loader::PD_AUTHORITY_TAG) != Some(1) {
        return Err(SijkaError::NotUpgradeAuthority);
    }
    match read_key(data, loader::PD_AUTHORITY) {
        Some(k) if pubkey_eq(k, payer) => Ok(()),
        _ => Err(SijkaError::NotUpgradeAuthority),
    }
}

/// Ember state contents for `initialize` (SPEC §5.1.0 #6, §3.9): length,
/// discriminator, `@104 == PHOENIX_PROGRAM_ID`, non-zero `input_mint`.
/// Returns `(usdc_mint = @40, output_mint = @72)`; the caller compares
/// `output_mint` with `GC@296`.
pub fn read_ember_state_init(data: &[u8]) -> Result<(Pubkey, Pubkey), SijkaError> {
    let e = SijkaError::InvalidEmberAccount;
    if data.len() < eml::MIN_LEN || array_ref::<8>(data, eml::DISCRIMINATOR) != Some(&DISC_EMBER_STATE) {
        return Err(e);
    }
    match read_key(data, eml::PHOENIX_PROGRAM) {
        Some(k) if pubkey_eq(k, &PHOENIX_PROGRAM_ID) => {}
        _ => return Err(e),
    }
    let usdc = *read_key(data, eml::INPUT_MINT).ok_or(e)?;
    let out = *read_key(data, eml::OUTPUT_MINT).ok_or(e)?;
    if is_zero_key(&usdc) {
        return Err(e);
    }
    Ok((usdc, out))
}

/// `@72 == GC@296` (SPEC §5.1.0 #6), with a non-zero PhUSD mint.
pub fn check_phusd_binding(gc_canonical_mint: &Pubkey, ember_output_mint: &Pubkey) -> Result<(), SijkaError> {
    if is_zero_key(gc_canonical_mint) {
        return Err(SijkaError::InvalidPhoenixGlobalConfig);
    }
    if !pubkey_eq(gc_canonical_mint, ember_output_mint) {
        return Err(SijkaError::InvalidEmberAccount);
    }
    Ok(())
}

/// Everything `initialize` writes, computed before any account is created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitPlan {
    pub admin: Pubkey,
    pub creator_payout: Pubkey,
    pub quote_mint: Pubkey,
    pub usdc_mint: Pubkey,
    pub phusd_mint: Pubkey,
    pub harvest_params: [u8; 64],
    pub inflow_params: [u8; 40],
    pub pdas: ProgramPdas,
    pub vault_usdc: Pubkey,
    pub vault_phusd: Pubkey,
    pub swap_wsol: Pubkey,
    pub swap_usdc: Pubkey,
    pub creator_usdc: Pubkey,
    pub creator_escrow_usdc: Pubkey,
    pub buyback_usdc: Pubkey,
    pub emergency_recipient_usdc: Pubkey,
    pub emergency_recipient_phusd: Pubkey,
}

/// SPEC §5.1.0 step 7: the canonical ATAs (all under SPL Token).
pub fn build_init_plan(
    a: &InitArgs<'_>,
    usdc: &Pubkey,
    phusd: &Pubkey,
    pdas: ProgramPdas,
) -> Result<InitPlan, ProgramError> {
    let ata = |owner: &Pubkey, mint: &Pubkey| pda::find_ata(owner, &SPL_TOKEN_PROGRAM_ID, mint);
    Ok(InitPlan {
        admin: *a.admin,
        creator_payout: *a.creator_payout,
        quote_mint: *a.quote_mint,
        usdc_mint: *usdc,
        phusd_mint: *phusd,
        harvest_params: *a.harvest_params,
        inflow_params: *a.inflow_params,
        vault_usdc: ata(&pdas.phx_authority.key, usdc)?,
        vault_phusd: ata(&pdas.phx_authority.key, phusd)?,
        swap_wsol: ata(&pdas.swap_authority.key, &WSOL_MINT)?,
        swap_usdc: ata(&pdas.swap_authority.key, usdc)?,
        creator_usdc: ata(a.creator_payout, usdc)?,
        creator_escrow_usdc: ata(&pdas.creator_escrow.key, usdc)?,
        buyback_usdc: ata(&pdas.buyback_authority.key, usdc)?,
        emergency_recipient_usdc: ata(a.admin, usdc)?,
        emergency_recipient_phusd: ata(a.admin, phusd)?,
        pdas,
    })
}

/// SPEC §5.1.0 step 9: the whole `Config` (every other byte zero; `trader =
/// 0`, trading off until tag 3; `last_harvest_ts = ts − t_min_secs`, DECISIONS
/// §23 item 7).
pub fn write_config(buf: &mut [u8], p: &InitPlan, ts: i64) -> Result<(), ProgramError> {
    let mut c = ConfigMut::new(buf).ok_or_else(|| SijkaError::InvariantViolated.fail())?;
    c.bytes_mut().fill(0);
    c.set_discriminator(&DISC_CONFIG);
    c.set_version(CONFIG_VERSION);
    c.set_creator_share_bps(CREATOR_SHARE_BPS_U16);
    c.set_admin(&p.admin);
    c.set_creator_payout(&p.creator_payout);
    c.set_quote_mint(&p.quote_mint);
    c.set_usdc_mint(&p.usdc_mint);
    c.set_phusd_mint(&p.phusd_mint);
    c.set_fee_inbox(&p.pdas.fee_inbox.key);
    c.set_phx_authority(&p.pdas.phx_authority.key);
    c.set_swap_authority(&p.pdas.swap_authority.key);
    c.set_buyback_authority(&p.pdas.buyback_authority.key);
    c.set_rent_payer(&p.pdas.rent_payer.key);
    c.set_vault_usdc(&p.vault_usdc);
    c.set_vault_phusd(&p.vault_phusd);
    c.set_creator_usdc(&p.creator_usdc);
    c.set_buyback_usdc(&p.buyback_usdc);
    c.set_config_bump(p.pdas.config.bump);
    c.set_fee_inbox_bump(p.pdas.fee_inbox.bump);
    c.set_phx_authority_bump(p.pdas.phx_authority.bump);
    c.set_swap_authority_bump(p.pdas.swap_authority.bump);
    c.set_buyback_authority_bump(p.pdas.buyback_authority.bump);
    c.set_rent_payer_bump(p.pdas.rent_payer.bump);
    c.set_created_ts(ts);
    // DECISIONS §23 item 7: the first harvest is allowed right after
    // initialize (`now ≥ last_harvest_ts + t_min_secs` holds from `ts` on);
    // every later one waits `T_min` (SPEC §5.4.2 step 2).
    let t_min = HarvestParams::from_array(&p.harvest_params).t_min_secs();
    c.set_last_harvest_ts(initial_last_harvest_ts(ts, t_min).map_err(SijkaError::fail)?);
    c.set_harvest_params(&p.harvest_params);
    c.set_buyback_state(&p.pdas.buyback_state.key);
    c.set_bb_unwrap(&p.pdas.bb_unwrap.key);
    c.set_buyback_state_bump(p.pdas.buyback_state.bump);
    c.set_bb_unwrap_bump(p.pdas.bb_unwrap.bump);
    c.set_creator_escrow_bump(p.pdas.creator_escrow.bump);
    c.set_inflow_params(&p.inflow_params);
    c.set_swap_wsol(&p.swap_wsol);
    c.set_swap_usdc(&p.swap_usdc);
    c.set_creator_escrow(&p.pdas.creator_escrow.key);
    c.set_creator_escrow_usdc(&p.creator_escrow_usdc);
    // DECISIONS §17: the emergency recipient is the admin at initialize and
    // is never written again.
    c.set_emergency_recipient(&p.admin);
    c.set_emergency_recipient_usdc(&p.emergency_recipient_usdc);
    c.set_emergency_recipient_phusd(&p.emergency_recipient_phusd);
    Ok(())
}

/// State account slot of `initialize`: the derived PDA, writable, and not
/// yet created (System, no data; pre-funded lamports are fine).
fn check_new_state_account(ai: &AccountInfo, expected: &Pubkey) -> ProgramResult {
    expect_key(ai, expected, SijkaError::InvalidPda)?;
    expect_writable(ai)?;
    if !ai.is_owned_by(&SYSTEM_PROGRAM_ID) || ai.data_len() != 0 {
        return Err(SijkaError::ConfigAlreadyInitialized.fail());
    }
    Ok(())
}

/// `create_pda_account` for `config`, signed by its seeds,
/// then check that the account really is ours with the expected size.
fn create_state_account(
    payer: &AccountInfo,
    target: &AccountInfo,
    space: usize,
    program_id: &Pubkey,
    seed: &'static [u8],
    bump: u8,
) -> ProgramResult {
    let pda = PdaSeeds::new(seed, bump);
    let seeds = pda.seeds();
    let signer = [Signer::from(&seeds)];
    create_pda_account(payer, target, space, program_id, &signer, SijkaError::ConfigAlreadyInitialized)?;
    if !target.is_owned_by(program_id) || target.data_len() != space {
        return Err(SijkaError::InvariantViolated.fail());
    }
    Ok(())
}

/// Tag 0 `initialize` (SPEC §5.1.0).
#[inline(never)]
pub fn initialize(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    initialize_at(program_id, accounts, data, runtime_now)
}

#[inline(never)]
fn initialize_at(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8], now: ClockFn) -> ProgramResult {
    check_shape(&INITIALIZE, accounts, data)?;
    let [payer, config, program_data, system_program, global_config, ember_state] = accounts else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };

    // #0 payer = upgrade authority of this program (#2 ProgramData). Only the
    // deployer can initialize, so the vault cannot be set up by a front-runner.
    if !payer.is_signer() {
        return Err(SijkaError::NotUpgradeAuthority.fail());
    }
    expect_writable(payer)?;
    let (pd_key, _) = pda::find(&[program_id.as_slice()], &BPF_LOADER_UPGRADEABLE_ID)?;
    expect_key(program_data, &pd_key, SijkaError::InvalidExternalAccount)?;
    expect_owner(program_data, &BPF_LOADER_UPGRADEABLE_ID, SijkaError::InvalidExternalAccount)?;
    {
        let d = program_data.try_borrow_data()?;
        check_program_data(&d, payer.key()).map_err(SijkaError::fail)?;
    }
    // #3
    expect_key(system_program, &SYSTEM_PROGRAM_ID, SijkaError::InvalidProgramId)?;

    // #1 (step 4: all PDAs and bumps).
    let pdas = ProgramPdas::derive(program_id)?;
    check_new_state_account(config, &pdas.config.key)?;

    // #5 Ember state (step 2: usdc_mint = ember_state@40).
    expect_key(ember_state, &EMBER_STATE, SijkaError::InvalidEmberAccount)?;
    expect_owner(ember_state, &EMBER_PROGRAM_ID, SijkaError::InvalidEmberAccount)?;
    let (usdc_mint, ember_phusd) = {
        let d = ember_state.try_borrow_data()?;
        read_ember_state_init(&d).map_err(SijkaError::fail)?
    };

    // Steps 3, 5, 6.
    let args = parse_init_args(data)?;
    check_init_args(&args, &usdc_mint, &pdas).map_err(SijkaError::fail)?;

    // #4 GlobalConfig (§5.0.5, read-only): phusd_mint = GC@296 = ember_state@72.
    let gc = check_global_config(global_config, GC_MIN_LEN, false)?;
    check_phusd_binding(&gc.canonical_mint, &ember_phusd).map_err(SijkaError::fail)?;

    // Step 7.
    let plan = build_init_plan(&args, &usdc_mint, &gc.canonical_mint, pdas)?;
    let t = now()?;

    // Step 6.
    create_state_account(payer, config, CONFIG_LEN, program_id, SEED_CONFIG, plan.pdas.config.bump)?;

    // Step 7.
    {
        let mut d = config.try_borrow_mut_data()?;
        write_config(&mut d, &plan, t.ts)?;
    }

    // Step 8.
    EvInitialize {
        ts: t.ts,
        admin: &plan.admin,
        creator_payout: &plan.creator_payout,
        quote_mint: &plan.quote_mint,
        usdc_mint: &plan.usdc_mint,
        phusd_mint: &plan.phusd_mint,
        config_version: CONFIG_VERSION,
    }
    .emit()
}

// ================================================================ tag 1 ====

/// SIJKA mint checks (SPEC §5.1.1 step 2, §3.9, U-26). `owner` is the mint's
/// owner program. Mint and freeze authority must be `None`, the mint
/// initialized; SPL Token: exactly 82 bytes; Token-2022: at least 166 bytes,
/// account type Mint, and a TLV area with only MetadataPointer (18) and
/// TokenMetadata (19). Returns `decimals`.
pub fn check_mint(owner: &Pubkey, data: &[u8]) -> Result<u8, SijkaError> {
    let e = SijkaError::InvalidTokenMint;
    let t22 = if pubkey_eq(owner, &SPL_TOKEN_PROGRAM_ID) {
        false
    } else if pubkey_eq(owner, &TOKEN_2022_PROGRAM_ID) {
        true
    } else {
        return Err(e);
    };
    let len_ok = if t22 { data.len() >= ml::T22_TLV_START } else { data.len() == ml::LEN };
    if !len_ok {
        return Err(e);
    }
    if read_u32(data, ml::MINT_AUTHORITY_TAG) != Some(0)
        || read_u8(data, ml::IS_INITIALIZED) != Some(1)
        || read_u32(data, ml::FREEZE_AUTHORITY_TAG) != Some(0)
    {
        return Err(e);
    }
    let decimals = read_u8(data, ml::DECIMALS).ok_or(e)?;
    if t22 {
        if read_u8(data, ml::T22_ACCOUNT_TYPE) != Some(ml::T22_ACCOUNT_TYPE_MINT) {
            return Err(e);
        }
        check_mint_tlv(data)?;
    }
    Ok(decimals)
}

/// Token-2022 TLV walk from `@166`: `type u16, len u16, value`. `type == 0`
/// ends the list; any type other than 18 / 19 is rejected; a record running
/// past the end, or a partial header at the end, is rejected.
fn check_mint_tlv(data: &[u8]) -> Result<(), SijkaError> {
    let e = SijkaError::InvalidTokenMint;
    let len = data.len();
    let mut off = ml::T22_TLV_START;
    loop {
        let value_start = off.checked_add(4).ok_or(e)?;
        if value_start > len {
            break;
        }
        let ty = read_u16(data, off).ok_or(e)?;
        if ty == 0 {
            return Ok(());
        }
        if ty != ml::EXT_METADATA_POINTER && ty != ml::EXT_TOKEN_METADATA {
            return Err(e);
        }
        let l = read_u16(data, off.checked_add(2).ok_or(e)?).ok_or(e)?;
        off = value_start.checked_add(usize::from(l)).ok_or(e)?;
        if off > len {
            return Err(e);
        }
    }
    if off == len { Ok(()) } else { Err(e) }
}

/// `SharingConfig` checks (SPEC §5.1.1 step 3, U-9): pump_fees v2 config for
/// `mint`, active, admin revoked (locked), exactly one shareholder
/// `fee_inbox` with 100%, at `create_program_address(["sharing-config",
/// mint, [bump]], PUMP_FEES_PROGRAM)`. The owner is checked by the caller.
pub fn check_sharing_config(key: &Pubkey, data: &[u8], mint: &Pubkey, fee_inbox: &Pubkey) -> Result<(), SijkaError> {
    let e = SijkaError::InvalidSharingConfig;
    let s = read_sharing_config(data).ok_or(e)?;
    let first_ok = matches!(s.first, Some((addr, bps)) if pubkey_eq(&addr, fee_inbox) && bps == 10_000);
    let ok = s.discriminator == SHARING_CONFIG_DISC
        && s.version == 2
        && s.status == 1
        && pubkey_eq(&s.mint, mint)
        && s.admin_revoked == 1
        && s.shareholders == 1
        && first_ok;
    if !ok {
        return Err(e);
    }
    match pda::create(&[SEED_PUMP_SHARING_CONFIG, mint, &[s.bump]], &PUMP_FEES_PROGRAM) {
        Ok(k) if pubkey_eq(&k, key) => Ok(()),
        _ => Err(e),
    }
}

/// Tag 1 `set_token_mint` (SPEC §5.1.1).
#[inline(never)]
pub fn set_token_mint(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    set_token_mint_at(program_id, accounts, data, runtime_now)
}

#[inline(never)]
fn set_token_mint_at(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8], now: ClockFn) -> ProgramResult {
    check_shape(&SET_TOKEN_MINT, accounts, data)?;
    let [admin, config, token_mint, sharing_config] = accounts else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    let mut cfg_ref = load_config_mut(config, program_id)?;
    let mut cfg = config_view_mut(&mut cfg_ref)?;
    let (fee_inbox, buyback_authority) = {
        let v = cfg.view();
        check_admin(admin, &v)?;
        // Step 1: written exactly once (Config invariant 4).
        if !is_zero_key(v.token_mint()) {
            return Err(SijkaError::TokenMintAlreadySet.fail());
        }
        (*v.fee_inbox(), *v.buyback_authority())
    };

    // #2, step 2.
    let token_program = *token_mint.owner();
    let decimals = {
        let d = token_mint.try_borrow_data()?;
        check_mint(&token_program, &d).map_err(SijkaError::fail)?
    };
    // #3, step 3.
    expect_owner(sharing_config, &PUMP_FEES_PROGRAM, SijkaError::InvalidSharingConfig)?;
    {
        let d = sharing_config.try_borrow_data()?;
        check_sharing_config(sharing_config.key(), &d, token_mint.key(), &fee_inbox).map_err(SijkaError::fail)?;
    }

    // Step 4.
    let buyback_token = pda::find_ata(&buyback_authority, &token_program, token_mint.key())?;
    let t = now()?;
    cfg.set_token_mint(token_mint.key());
    cfg.set_token_program(&token_program);
    cfg.set_token_decimals(decimals);
    cfg.set_buyback_token(&buyback_token);
    cfg.set_token_mint_set_ts(t.ts);
    stamp_admin(&mut cfg, &t);

    // Step 5.
    EvTokenMintSet {
        ts: t.ts,
        token_mint: token_mint.key(),
        token_program: &token_program,
        decimals,
        sharing_config: sharing_config.key(),
        buyback_token: &buyback_token,
    }
    .emit()
}

// ================================================================ tag 2 ====

/// Trader header after registration (SPEC §5.1.2 step 4): discriminator,
/// own key, authority and position authority `== phx_authority` (the program
/// never appoints a delegate), indices 0/0.
pub fn check_trader_header(
    data: &[u8],
    trader_key: &Pubkey,
    phx_authority: &Pubkey,
) -> Result<TraderHeader, SijkaError> {
    let e = SijkaError::InvalidPhoenixTraderAccount;
    if array_ref::<8>(data, 0) != Some(&DISC_TRADER) {
        return Err(e);
    }
    let h = trader_header(data).ok_or(e)?;
    let ok = pubkey_eq(&h.trader_key, trader_key)
        && pubkey_eq(&h.authority, phx_authority)
        && pubkey_eq(&h.position_authority, phx_authority)
        && h.pda_index == 0
        && h.subaccount_index == 0;
    if ok { Ok(h) } else { Err(e) }
}

/// Tag 2 `register_phoenix_trader` (SPEC §5.1.2).
#[inline(never)]
pub fn register_phoenix_trader(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    register_phoenix_trader_at(program_id, accounts, data, runtime_now)
}

#[inline(never)]
fn register_phoenix_trader_at(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    now: ClockFn,
) -> ProgramResult {
    check_shape(&REGISTER_PHOENIX_TRADER, accounts, data)?;
    let [
        admin,
        config,
        phx_authority,
        rent_payer,
        phoenix_program,
        log_authority,
        global_config,
        trader_account,
        system_program,
    ] = accounts
    else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    let trader_bump = data_u8(data, 1)?;

    // Read what the checks need; the Config borrow ends before the CPI.
    let (phx_key, rent_payer_key, rent_payer_bump) = {
        let cfg_ref = load_config_mut(config, program_id)?;
        let cfg = config_view(&cfg_ref)?;
        check_admin(admin, &cfg)?;
        // Step 1.
        if !is_zero_key(cfg.phoenix_trader()) {
            return Err(SijkaError::TraderAlreadyRegistered.fail());
        }
        (*cfg.phx_authority(), *cfg.rent_payer(), cfg.rent_payer_bump())
    };

    // #2 (does not sign the CPI), #3 .. #8.
    expect_key(phx_authority, &phx_key, SijkaError::InvalidPda)?;
    expect_key(rent_payer, &rent_payer_key, SijkaError::InvalidPda)?;
    expect_writable(rent_payer)?;
    expect_system_empty(rent_payer, SijkaError::InvalidExternalAccount)?;
    expect_program(phoenix_program, &PHOENIX_PROGRAM_ID)?;
    expect_key(log_authority, &PHOENIX_LOG_AUTHORITY, SijkaError::InvalidExternalAccount)?;
    expect_key(system_program, &SYSTEM_PROGRAM_ID, SijkaError::InvalidProgramId)?;
    pda::expect_pda(
        trader_account,
        &[SEED_PHOENIX_TRADER, &phx_key, &[0, 0], &[trader_bump]],
        &PHOENIX_PROGRAM_ID,
        SijkaError::InvalidPhoenixTraderPda,
    )?;
    expect_writable(trader_account)?;
    check_global_config(global_config, GC_MIN_LEN, false)?;

    let created_by_program = if trader_account.data_is_empty() {
        // Step 2: rent of the 128-position trader plus rent(0) that keeps
        // `rent_payer` itself rent-exempt.
        let need = add_u64(rent_exempt_minimum(TRADER_ACCOUNT_LEN)?, rent_exempt_minimum(0)?)?;
        if rent_payer.lamports() < need {
            return Err(SijkaError::RentPayerUnderfunded.fail());
        }
        let cpi = phoenix::RegisterTrader {
            phoenix_program,
            log_authority,
            global_config,
            payer: rent_payer,
            trader: phx_authority,
            trader_account,
            system_program,
        };
        let args =
            phoenix::RegisterTraderArgs::new(TRADER_MAX_POSITIONS, 0, 0).with_trader_preference_bits(TRADER_PREFS);
        let pda = PdaSeeds::new(SEED_RENT_PAYER, rent_payer_bump);
        let seeds = pda.seeds();
        let signer = [Signer::from(&seeds)];
        let mut scratch = CpiScratch::<SCRATCH_REGISTER_ACCOUNTS, SCRATCH_REGISTER_DATA>::new(phoenix_program);
        phx_register(&cpi, args, &signer, &mut scratch)?;
        1u8
    } else {
        // Step 3: someone registered first (front-run). Accepted as is; the
        // header must still be ours (step 4) and the actual prefs are recorded.
        0u8
    };

    // Steps 3–4 (both paths).
    expect_owner(trader_account, &PHOENIX_PROGRAM_ID, SijkaError::InvalidPhoenixTraderAccount)?;
    let h = {
        let d = trader_account.try_borrow_data()?;
        check_trader_header(&d, trader_account.key(), &phx_key).map_err(SijkaError::fail)?
    };

    // Step 5 (all writes after the CPI).
    let t = now()?;
    {
        let mut cfg_ref = load_config_mut(config, program_id)?;
        let mut cfg = config_view_mut(&mut cfg_ref)?;
        cfg.set_phoenix_trader(trader_account.key());
        cfg.set_phoenix_trader_bump(trader_bump);
        cfg.set_trader_preference_bits(h.preference_bits);
        cfg.set_trader_max_positions(h.max_positions);
        cfg.set_trader_registered_by_program(created_by_program);
        cfg.set_trader_registered_ts(t.ts);
        stamp_admin(&mut cfg, &t);
    }

    // Step 6.
    EvTraderRegistered {
        ts: t.ts,
        phoenix_trader: trader_account.key(),
        prefs: h.preference_bits,
        max_positions: h.max_positions,
        created_by_program,
        funding_key: &h.funding_key,
        flags: h.flags,
    }
    .emit()
}

// ================================================================ tag 3 ====

/// Tag 3 `set_trader` (SPEC §5.1.3): the admin sets the trading key, the only
/// signer of tag 10 `trade`, at once. 0 turns trading off; a program PDA may
/// never hold the role. Works in recovery mode too (the key closes positions,
/// §5.6.5); `trader_account` is not read.
#[inline(never)]
pub fn set_trader(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    set_trader_at(program_id, accounts, data, runtime_now)
}

#[inline(never)]
fn set_trader_at(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8], now: ClockFn) -> ProgramResult {
    check_shape(&SET_TRADER, accounts, data)?;
    let [admin, config] = accounts else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    let new_trader = *data_key(data, 1)?;
    let mut cfg_ref = load_config_mut(config, program_id)?;
    let mut cfg = config_view_mut(&mut cfg_ref)?;
    let old = {
        let v = cfg.view();
        // Step 1.
        check_admin(admin, &v)?;
        // Step 2.
        check_role_key(&new_trader, &v, config.key()).map_err(SijkaError::fail)?;
        *v.trader()
    };
    // Step 3.
    let t = now()?;
    cfg.set_trader(&new_trader);
    stamp_admin(&mut cfg, &t);
    // Step 4.
    EvTraderSet { ts: t.ts, old_value: &old, new_value: &new_trader }.emit()
}

/// SPEC §5.1.3 / §5.1.10 step 2: the new trading or keeper key is not one of
/// the nine program PDAs (a PDA cannot sign an outer transaction, and
/// `phx_authority` as the trading key would mix T1 with T7). Zero (role off)
/// is allowed.
pub fn check_role_key(new_key: &Pubkey, cfg: &Config<'_>, config_key: &Pubkey) -> Result<(), SijkaError> {
    if stored_pdas(cfg, config_key).iter().any(|k| pubkey_eq(k, new_key)) {
        return Err(SijkaError::InvalidParams);
    }
    Ok(())
}

// =============================================================== tag 28 ====

/// Tag 28 `set_keeper` (SPEC §5.1.10, DECISIONS §23 items 3 and 4): the admin
/// sets the keeper key, the only signer of the swaps (tag 20
/// `swap_sol_to_usdc`, tag 43 `bb_swap_usdc_to_sol`) and of the buyback chunks
/// (tags 44, 45), at once. 0 turns them off; a program PDA may never hold the
/// role (same rule as `set_trader`). Works in recovery mode too (the buyback
/// goes on). The off-chain scripts also
/// refuse `keeper == admin` and `keeper == trader` (not checked on chain: the
/// admin could set either key anyway).
#[inline(never)]
pub fn set_keeper(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    set_keeper_at(program_id, accounts, data, runtime_now)
}

#[inline(never)]
fn set_keeper_at(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8], now: ClockFn) -> ProgramResult {
    check_shape(&SET_KEEPER, accounts, data)?;
    let [admin, config] = accounts else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    let new_keeper = *data_key(data, 1)?;
    let mut cfg_ref = load_config_mut(config, program_id)?;
    let mut cfg = config_view_mut(&mut cfg_ref)?;
    let old = {
        let v = cfg.view();
        // Step 1.
        check_admin(admin, &v)?;
        // Step 2.
        check_role_key(&new_keeper, &v, config.key()).map_err(SijkaError::fail)?;
        *v.keeper()
    };
    // Step 3.
    let t = now()?;
    cfg.set_keeper(&new_keeper);
    stamp_admin(&mut cfg, &t);
    // Step 4.
    EvKeeperSet { ts: t.ts, old_value: &old, new_value: &new_keeper }.emit()
}

// ================================================================ tests ====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DISC_GLOBAL_CONFIG, HAWKEYE_PROGRAM_ID, PHOENIX_GLOBAL_CONFIG, PUMP_PROGRAM};
    use crate::external::layout::{global_config as gcl, trader as trl};
    use crate::state::config::FIELDS as CONFIG_FIELDS;
    use crate::state::config::harvest_params::HarvestParamsMut;
    use crate::state::config::inflow_params::InflowParamsMut;
    use crate::util::bytes::ZERO_KEY;
    use crate::util::test_utils::TestAccount;

    const PROGRAM: Pubkey = [0x11; 32];
    const ADMIN: Pubkey = [0xAD; 32];
    const TRADER: Pubkey = [0x7E; 32];
    const CREATOR: Pubkey = [0xCE; 32];
    const PAYER: Pubkey = [0xFA; 32];
    const USDC: Pubkey = [0xC1; 32];
    const PHUSD: Pubkey = [0xB2; 32];
    const MINT: Pubkey = [0x5A; 32];
    const NATIVE_LOADER: Pubkey = [0x0E; 32];
    const NOW: Now = Now { ts: 1_800_000_000, slot: 450_000_000 };
    const CREATED_TS: i64 = 1_700_000_000;

    fn t_now() -> Result<Now, ProgramError> {
        Ok(NOW)
    }

    type Handler = fn(&Pubkey, &[AccountInfo], &[u8], ClockFn) -> ProgramResult;
    /// One mutation of a test account and the error it must produce.
    type MutCase = (fn(&mut Acc), SijkaError);
    /// As [`MutCase`], for the account at a given slot.
    type SlotCase = (usize, fn(&mut Acc), SijkaError);

    /// Description of one test account (built fresh for every run).
    #[derive(Clone, Debug)]
    struct Acc {
        key: Pubkey,
        owner: Pubkey,
        lamports: u64,
        data: Vec<u8>,
        signer: bool,
        writable: bool,
        exec: bool,
    }

    impl Acc {
        fn new(key: Pubkey, owner: Pubkey, data: Vec<u8>) -> Self {
            Self { key, owner, lamports: 1_000_000_000, data, signer: false, writable: false, exec: false }
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
        fn empty(mut self) -> Self {
            self.lamports = 0;
            self
        }
        fn build(&self) -> TestAccount {
            TestAccount::new(self.key, self.owner, self.lamports, &self.data, self.signer, self.writable, self.exec)
        }
    }

    /// Run a handler over fresh accounts; returns the result and the accounts
    /// (to read back the state).
    fn run(f: Handler, accs: &[Acc], data: &[u8]) -> (ProgramResult, Vec<TestAccount>) {
        let t: Vec<TestAccount> = accs.iter().map(Acc::build).collect();
        let r = {
            let infos: Vec<AccountInfo> = t.iter().map(TestAccount::info).collect();
            f(&PROGRAM, &infos, data, t_now)
        };
        (r, t)
    }

    fn res(f: Handler, accs: &[Acc], data: &[u8]) -> ProgramResult {
        run(f, accs, data).0
    }

    fn err(e: SijkaError) -> ProgramResult {
        Err(e.into())
    }

    fn pdas() -> ProgramPdas {
        ProgramPdas::derive(&PROGRAM).unwrap()
    }

    /// All checks passed and the handler reached the Rent sysvar (account
    /// creation in tag 0, the rent-payer check in tag 2): on the host the Rent
    /// sysvar is unavailable, so the handler stops there.
    fn reached_rent(r: ProgramResult) -> bool {
        r == Err(ProgramError::UnsupportedSysvar)
    }

    // ---------------------------------------------------------- params ----

    fn harvest_params() -> [u8; 64] {
        let mut b = [0u8; 64];
        let mut m = HarvestParamsMut::from_array(&mut b);
        m.set_epsilon(1_000_000);
        m.set_d_min(25_000_000);
        m.set_margin_buffer_abs(5_000_000);
        m.set_max_harvest_per_call(250_000_000_000);
        m.set_t_min_secs(604_800);
        m.set_margin_buffer_im_bps(5_000);
        m.set_max_buyback_backlog(50_000_000_000);
        m.set_harvest_mark_max_age_slots(150);
        b
    }

    fn inflow_params() -> [u8; 40] {
        let mut b = [0u8; 40];
        let mut m = InflowParamsMut::from_array(&mut b);
        m.set_swap_max_lamports(10_000_000_000);
        m.set_swap_min_lamports(50_000_000);
        m.set_deposit_min_atoms(1_000_000);
        b
    }

    // ------------------------------------------------------- initialize ----

    fn init_data(admin: &Pubkey, creator: &Pubkey, quote: &Pubkey) -> Vec<u8> {
        let mut d = vec![0u8; 201];
        d[1..33].copy_from_slice(admin);
        d[33..65].copy_from_slice(creator);
        d[65..97].copy_from_slice(quote);
        d[97..161].copy_from_slice(&harvest_params());
        d[161..201].copy_from_slice(&inflow_params());
        d
    }

    fn good_init_data() -> Vec<u8> {
        init_data(&ADMIN, &CREATOR, &WSOL_MINT)
    }

    fn plan() -> InitPlan {
        let d = good_init_data();
        let a = parse_init_args(&d).unwrap();
        build_init_plan(&a, &USDC, &PHUSD, pdas()).unwrap()
    }

    fn gc_data() -> Vec<u8> {
        let mut d = vec![0u8; 2560];
        let mut put = |off: usize, k: &Pubkey| d[off..off + 32].copy_from_slice(k);
        put(gcl::ACCOUNT_KEY, &PHOENIX_GLOBAL_CONFIG);
        put(gcl::CANONICAL_MINT, &PHUSD);
        put(gcl::GLOBAL_VAULT, &[0x61; 32]);
        put(gcl::PERP_ASSET_MAP, &[0x62; 32]);
        put(gcl::GTI_HEADER, &[0x63; 32]);
        put(gcl::ATB_HEADER, &[0x64; 32]);
        put(gcl::WITHDRAW_QUEUE, &[0x65; 32]);
        d[0..8].copy_from_slice(&DISC_GLOBAL_CONFIG);
        d[gcl::EXCHANGE_STATUS] = 0b1000_0011;
        d[gcl::QUOTE_DECIMALS] = 6;
        d
    }

    fn gc_acc() -> Acc {
        Acc::new(PHOENIX_GLOBAL_CONFIG, PHOENIX_PROGRAM_ID, gc_data())
    }

    fn ember_data() -> Vec<u8> {
        let mut d = vec![0u8; 136];
        d[0..8].copy_from_slice(&DISC_EMBER_STATE);
        d[40..72].copy_from_slice(&USDC);
        d[72..104].copy_from_slice(&PHUSD);
        d[104..136].copy_from_slice(&PHOENIX_PROGRAM_ID);
        d
    }

    fn program_data(authority: Option<&Pubkey>) -> Vec<u8> {
        let mut d = vec![0u8; 45 + 16];
        d[0..4].copy_from_slice(&3u32.to_le_bytes());
        d[4..12].copy_from_slice(&7u64.to_le_bytes());
        if let Some(p) = authority {
            d[12] = 1;
            d[13..45].copy_from_slice(p);
        }
        d
    }

    fn init_accounts() -> Vec<Acc> {
        let p = pdas();
        let (pd_key, _) = pda::find(&[PROGRAM.as_slice()], &BPF_LOADER_UPGRADEABLE_ID).unwrap();
        vec![
            Acc::new(PAYER, SYSTEM_PROGRAM_ID, vec![]).s().w(),
            Acc::new(p.config.key, SYSTEM_PROGRAM_ID, vec![]).w().empty(),
            Acc::new(pd_key, BPF_LOADER_UPGRADEABLE_ID, program_data(Some(&PAYER))),
            Acc::new(SYSTEM_PROGRAM_ID, NATIVE_LOADER, vec![]).x(),
            gc_acc(),
            Acc::new(EMBER_STATE, EMBER_PROGRAM_ID, ember_data()),
        ]
    }

    fn run_init(accs: &[Acc], data: &[u8]) -> ProgramResult {
        res(initialize_at, accs, data)
    }

    #[test]
    fn initialize_valid_input_reaches_account_creation() {
        assert!(reached_rent(run_init(&init_accounts(), &good_init_data())));
        // USDC pair.
        let d = init_data(&ADMIN, &CREATOR, &USDC);
        assert!(reached_rent(run_init(&init_accounts(), &d)));
        // A pre-funded config address (TA-3) is fine.
        let mut a = init_accounts();
        a[1].lamports = 1;
        assert!(reached_rent(run_init(&a, &good_init_data())));
        // One wallet for every role (operator decision 2026-09-26): the upgrade
        // authority that pays is also the admin and the creator_payout wallet.
        // Nothing on chain refuses that.
        let d = init_data(&PAYER, &PAYER, &WSOL_MINT);
        assert!(reached_rent(run_init(&init_accounts(), &d)));
    }

    #[test]
    fn initialize_requires_upgrade_authority() {
        let d = good_init_data();
        let cases: [SlotCase; 8] = [
            (0, |a| a.signer = false, SijkaError::NotUpgradeAuthority),
            (0, |a| a.writable = false, SijkaError::AccountNotWritable),
            // Program without an upgrade authority, or with another one (TA-2).
            (2, |a| a.data = program_data(None), SijkaError::NotUpgradeAuthority),
            (2, |a| a.data = program_data(Some(&[0x99; 32])), SijkaError::NotUpgradeAuthority),
            // ProgramData of another program / wrong owner / wrong state / short.
            (2, |a| a.key = [0x42; 32], SijkaError::InvalidExternalAccount),
            (2, |a| a.owner = SYSTEM_PROGRAM_ID, SijkaError::InvalidExternalAccount),
            (2, |a| a.data[0] = 2, SijkaError::InvalidExternalAccount),
            (2, |a| a.data.truncate(44), SijkaError::InvalidExternalAccount),
        ];
        for (i, (slot, m, e)) in cases.iter().enumerate() {
            let mut a = init_accounts();
            m(&mut a[*slot]);
            assert_eq!(run_init(&a, &d), err(*e), "case {i}");
        }
    }

    #[test]
    fn initialize_state_account_slots() {
        let d = good_init_data();
        let mut a = init_accounts();
        a[3].key = [0x42; 32];
        assert_eq!(run_init(&a, &d), err(SijkaError::InvalidProgramId));
        {
            let i = 1usize;
            let cases: [MutCase; 4] = [
                (|a| a.key = [0x42; 32], SijkaError::InvalidPda),
                (|a| a.writable = false, SijkaError::AccountNotWritable),
                // Second initialize (TA-3): owned by the program with data.
                (
                    |a| {
                        a.owner = PROGRAM;
                        a.data = vec![0u8; 16];
                    },
                    SijkaError::ConfigAlreadyInitialized,
                ),
                (|a| a.data = vec![0u8; 1], SijkaError::ConfigAlreadyInitialized),
            ];
            for (m, e) in cases {
                let mut a = init_accounts();
                m(&mut a[i]);
                assert_eq!(run_init(&a, &d), err(e), "slot {i}");
            }
        }
        // Another PDA of this program at the config slot.
        let mut a = init_accounts();
        a[1].key = pdas().buyback_state.key;
        assert_eq!(run_init(&a, &d), err(SijkaError::InvalidPda));
    }

    #[test]
    fn initialize_ember_state_checks() {
        let d = good_init_data();
        let cases: [fn(&mut Acc); 6] = [
            |e| e.key = [0x42; 32],
            |e| e.owner = PHOENIX_PROGRAM_ID,
            |e| e.data[0] ^= 1,
            |e| e.data[104] ^= 1,
            |e| e.data.truncate(135),
            |e| e.data[40..72].fill(0),
        ];
        for (i, c) in cases.iter().enumerate() {
            let mut a = init_accounts();
            c(&mut a[5]);
            assert_eq!(run_init(&a, &d), err(SijkaError::InvalidEmberAccount), "case {i}");
        }
    }

    #[test]
    fn initialize_argument_checks() {
        let a = init_accounts();
        let bad = |d: Vec<u8>| run_init(&a, &d);
        assert_eq!(bad(init_data(&ADMIN, &CREATOR, &PHUSD)), err(SijkaError::InvalidQuoteMint));
        assert_eq!(bad(init_data(&ADMIN, &CREATOR, &ZERO_KEY)), err(SijkaError::InvalidQuoteMint));
        assert_eq!(bad(init_data(&ZERO_KEY, &CREATOR, &WSOL_MINT)), err(SijkaError::InvalidParams));
        assert_eq!(bad(init_data(&ADMIN, &ZERO_KEY, &WSOL_MINT)), err(SijkaError::InvalidParams));
        // No role may be a program PDA (every PDA × every role).
        for k in pdas().keys() {
            for role in 0..2 {
                let mut keys = [ADMIN, CREATOR];
                keys[role] = *k;
                let d = init_data(&keys[0], &keys[1], &WSOL_MINT);
                assert_eq!(bad(d), err(SijkaError::InvalidParams), "role {role}");
            }
        }
        // Structural parameter checks (one per block).
        let mut d = good_init_data();
        d[97 + 8..97 + 16].fill(0); // d_min = 0
        assert_eq!(bad(d), err(SijkaError::InvalidParams));
        // SPEC v4: the retired fields are reserved zeros (InitArgs keep their
        // length): InflowParams swap band / mark age (@0..4) and Ember
        // tolerance (@32..40); HarvestParams withdraw tolerance (@32..40,
        // @56..58).
        for i in (0..4).chain(32..40) {
            let mut d = good_init_data();
            d[161 + i] = 1;
            assert_eq!(bad(d), err(SijkaError::InvalidParams), "InflowParams byte {i}");
        }
        for i in (32..40).chain(56..58) {
            let mut d = good_init_data();
            d[97 + i] = 1;
            assert_eq!(bad(d), err(SijkaError::InvalidParams), "HarvestParams byte {i}");
        }
        // SPEC v4: the ACC-1 backlog gate cannot be switched on later, so 0 is refused.
        let mut d = good_init_data();
        d[97 + 48..97 + 56].fill(0);
        assert_eq!(bad(d), err(SijkaError::InvalidParams));
    }

    #[test]
    fn initialize_pure_checks() {
        assert_eq!(check_program_data(&program_data(Some(&PAYER)), &PAYER), Ok(()));
        assert_eq!(check_phusd_binding(&PHUSD, &PHUSD), Ok(()));
        assert_eq!(check_phusd_binding(&PHUSD, &USDC), Err(SijkaError::InvalidEmberAccount));
        assert_eq!(check_phusd_binding(&ZERO_KEY, &ZERO_KEY), Err(SijkaError::InvalidPhoenixGlobalConfig));
        assert_eq!(read_ember_state_init(&ember_data()), Ok((USDC, PHUSD)));
    }

    #[test]
    fn init_plan_derivations() {
        let p = plan();
        let ata = |o: &Pubkey, m: &Pubkey| pda::find_ata(o, &SPL_TOKEN_PROGRAM_ID, m).unwrap();
        assert_eq!(p.vault_usdc, ata(&p.pdas.phx_authority.key, &USDC));
        assert_eq!(p.vault_phusd, ata(&p.pdas.phx_authority.key, &PHUSD));
        assert_eq!(p.swap_wsol, ata(&p.pdas.swap_authority.key, &WSOL_MINT));
        assert_eq!(p.swap_usdc, ata(&p.pdas.swap_authority.key, &USDC));
        assert_eq!(p.creator_usdc, ata(&CREATOR, &USDC));
        assert_eq!(p.creator_escrow_usdc, ata(&p.pdas.creator_escrow.key, &USDC));
        assert_eq!(p.buyback_usdc, ata(&p.pdas.buyback_authority.key, &USDC));
        assert_eq!(p.emergency_recipient_usdc, ata(&ADMIN, &USDC));
        assert_eq!(p.emergency_recipient_phusd, ata(&ADMIN, &PHUSD));
        // Canonical PDAs from the documented seeds.
        let sp = solana_pubkey::Pubkey::new_from_array(PROGRAM);
        for (pda, seed) in [
            (p.pdas.config, SEED_CONFIG),
            (p.pdas.buyback_state, SEED_BUYBACK_STATE),
            (p.pdas.bb_unwrap, SEED_BB_UNWRAP),
            (p.pdas.fee_inbox, SEED_FEE_INBOX),
            (p.pdas.phx_authority, SEED_PHX_AUTHORITY),
            (p.pdas.swap_authority, SEED_SWAP_AUTHORITY),
            (p.pdas.buyback_authority, SEED_BUYBACK_AUTHORITY),
            (p.pdas.rent_payer, SEED_RENT_PAYER),
            (p.pdas.creator_escrow, SEED_CREATOR_ESCROW),
        ] {
            let (k, b) = solana_pubkey::Pubkey::find_program_address(&[seed], &sp);
            assert_eq!((pda.key, pda.bump), (k.to_bytes(), b));
        }
        assert!(crate::util::accounts::expect_distinct(&p.pdas.keys(), SijkaError::InvalidPda).is_ok());
    }

    fn base_config() -> Vec<u8> {
        let mut b = vec![0xEEu8; CONFIG_LEN];
        write_config(&mut b, &plan(), CREATED_TS).unwrap();
        b
    }

    #[test]
    fn write_config_sets_every_field_and_zeroes_the_rest() {
        let p = plan();
        let b = base_config();
        let c = Config::new(&b).unwrap();
        assert!(c.header_ok());
        assert_eq!(c.creator_share_bps(), 2000);
        assert_eq!(c.admin(), &ADMIN);
        assert_eq!(c.trader(), &ZERO_KEY, "no trading key before tag 3");
        assert_eq!(c.creator_payout(), &CREATOR);
        assert_eq!(c.quote_mint(), &WSOL_MINT);
        assert!(c.is_sol_pair());
        assert_eq!(c.usdc_mint(), &USDC);
        assert_eq!(c.phusd_mint(), &PHUSD);
        assert_eq!(c.fee_inbox(), &p.pdas.fee_inbox.key);
        assert_eq!(c.phx_authority(), &p.pdas.phx_authority.key);
        assert_eq!(c.swap_authority(), &p.pdas.swap_authority.key);
        assert_eq!(c.buyback_authority(), &p.pdas.buyback_authority.key);
        assert_eq!(c.rent_payer(), &p.pdas.rent_payer.key);
        assert_eq!(c.vault_usdc(), &p.vault_usdc);
        assert_eq!(c.vault_phusd(), &p.vault_phusd);
        assert_eq!(c.creator_usdc(), &p.creator_usdc);
        assert_eq!(c.buyback_usdc(), &p.buyback_usdc);
        assert_eq!(c.config_bump(), p.pdas.config.bump);
        assert_eq!(c.fee_inbox_bump(), p.pdas.fee_inbox.bump);
        assert_eq!(c.phx_authority_bump(), p.pdas.phx_authority.bump);
        assert_eq!(c.swap_authority_bump(), p.pdas.swap_authority.bump);
        assert_eq!(c.buyback_authority_bump(), p.pdas.buyback_authority.bump);
        assert_eq!(c.rent_payer_bump(), p.pdas.rent_payer.bump);
        assert_eq!(c.created_ts(), CREATED_TS);
        // DECISIONS §23 item 7: T_min (7 days in these params) already passed.
        assert_eq!(c.last_harvest_ts(), CREATED_TS - 604_800);
        assert_eq!(c.harvest_params(), &harvest_params());
        assert_eq!(c.buyback_state(), &p.pdas.buyback_state.key);
        assert_eq!(c.bb_unwrap(), &p.pdas.bb_unwrap.key);
        assert_eq!(c.buyback_state_bump(), p.pdas.buyback_state.bump);
        assert_eq!(c.bb_unwrap_bump(), p.pdas.bb_unwrap.bump);
        assert_eq!(c.creator_escrow_bump(), p.pdas.creator_escrow.bump);
        assert_eq!(c.inflow_params(), &inflow_params());
        assert_eq!(c.swap_wsol(), &p.swap_wsol);
        assert_eq!(c.swap_usdc(), &p.swap_usdc);
        assert_eq!(c.creator_escrow(), &p.pdas.creator_escrow.key);
        assert_eq!(c.creator_escrow_usdc(), &p.creator_escrow_usdc);
        assert_eq!(c.emergency_recipient(), &ADMIN);
        assert_eq!(c.emergency_recipient_usdc(), &p.emergency_recipient_usdc);
        assert_eq!(c.emergency_recipient_phusd(), &p.emergency_recipient_phusd);
        // Every field not written above is zero (counters, venue block,
        // recovery counters, reserved areas, mint and Phoenix trader slots).
        let written = [
            "discriminator",
            "version",
            "creator_share_bps",
            "admin",
            "creator_payout",
            "quote_mint",
            "usdc_mint",
            "phusd_mint",
            "fee_inbox",
            "phx_authority",
            "swap_authority",
            "buyback_authority",
            "rent_payer",
            "vault_usdc",
            "vault_phusd",
            "creator_usdc",
            "buyback_usdc",
            "config_bump",
            "fee_inbox_bump",
            "phx_authority_bump",
            "swap_authority_bump",
            "buyback_authority_bump",
            "rent_payer_bump",
            "created_ts",
            "last_harvest_ts",
            "harvest_params",
            "buyback_state",
            "bb_unwrap",
            "buyback_state_bump",
            "bb_unwrap_bump",
            "creator_escrow_bump",
            "inflow_params",
            "swap_wsol",
            "swap_usdc",
            "creator_escrow",
            "creator_escrow_usdc",
            "emergency_recipient",
            "emergency_recipient_usdc",
            "emergency_recipient_phusd",
        ];
        for f in CONFIG_FIELDS {
            if !written.contains(&f.name) {
                assert!(b[f.offset..f.offset + f.size].iter().all(|x| *x == 0), "field {} not zero", f.name);
            }
        }
        // The admin check works on the result.
        let admin = TestAccount::new(ADMIN, SYSTEM_PROGRAM_ID, 1, &[], true, false, false);
        assert!(check_admin(&admin.info(), &c).is_ok());
        assert!(write_config(&mut [0u8; 10], &p, 0).is_err());
    }

    /// DECISIONS §23 item 7: `initialize` anchors the `T_min` timer at
    /// `created_ts − t_min_secs`, so the harvest gate is open at `created_ts`
    /// for any `t_min_secs`; the subtraction is checked.
    #[test]
    fn write_config_opens_the_first_harvest_at_created_ts() {
        use crate::accounting::{GateInputs, HarvestStatus, QueueState, early_gate};
        for t_min in [0u32, 1, 3_600, 604_800, u32::MAX] {
            let mut p = plan();
            HarvestParamsMut::from_array(&mut p.harvest_params).set_t_min_secs(t_min);
            let mut b = vec![0u8; CONFIG_LEN];
            write_config(&mut b, &p, CREATED_TS).unwrap();
            let c = Config::new(&b).unwrap();
            assert_eq!(c.created_ts(), CREATED_TS);
            assert_eq!(c.last_harvest_ts(), CREATED_TS - i64::from(t_min), "t_min {t_min}");
            assert_eq!(c.harvest_count(), 0);
            let g = GateInputs {
                recovery_mode: 0,
                now: CREATED_TS,
                last_harvest_ts: c.last_harvest_ts(),
                t_min_secs: t_min,
                max_buyback_backlog: 0,
                buyback_usdc: 0,
                cooldown_slots: 0,
                last_deposit_slot: 0,
                slot: 0,
                queue: QueueState::UNPARSED,
            };
            assert_eq!(g.next_allowed_ts(), CREATED_TS);
            assert_eq!(early_gate(&g), HarvestStatus::Ready, "first harvest at created_ts, t_min {t_min}");
        }
        // Checked: a clock that cannot hold `created_ts − t_min_secs` fails
        // (MathOverflow) instead of wrapping.
        let mut b = vec![0u8; CONFIG_LEN];
        assert_eq!(write_config(&mut b, &plan(), i64::MIN), Err(ProgramError::Custom(SijkaError::MathOverflow.code())));
        assert!(write_config(&mut b, &plan(), i64::MIN + 604_800).is_ok());
    }

    // -------------------------------------------------- admin accounts ----

    fn admin_acc() -> Acc {
        Acc::new(ADMIN, SYSTEM_PROGRAM_ID, vec![]).s()
    }

    fn cfg_acc(data: Vec<u8>) -> Acc {
        Acc::new(pdas().config.key, PROGRAM, data).w()
    }

    fn data_of(t: &mut [TestAccount], i: usize) -> Vec<u8> {
        t[i].data_mut().to_vec()
    }

    /// A zeroed admin (never written since SPEC v4: no `renounce_admin`).
    fn zero_admin_config() -> Vec<u8> {
        let mut b = base_config();
        ConfigMut::new(&mut b).unwrap().set_admin(&ZERO_KEY);
        b
    }

    /// SPEC §5.0.4 admin check and the standard `config` check, for a handler
    /// whose accounts are `[admin, config, rest…]`.
    fn assert_admin_rules(f: Handler, rest: &[Acc], data: &[u8]) {
        let with = |admin: Acc, cfg: Acc| {
            let mut v = vec![admin, cfg];
            v.extend_from_slice(rest);
            res(f, &v, data)
        };
        let unsigned = Acc { signer: false, ..admin_acc() };
        assert_eq!(with(unsigned, cfg_acc(base_config())), err(SijkaError::Unauthorized));
        let other = Acc { key: [0x99; 32], ..admin_acc() };
        assert_eq!(with(other, cfg_acc(base_config())), err(SijkaError::Unauthorized));
        assert_eq!(with(admin_acc(), cfg_acc(zero_admin_config())), err(SijkaError::Unauthorized));
        let ro = Acc { writable: false, ..cfg_acc(base_config()) };
        assert_eq!(with(admin_acc(), ro), err(SijkaError::AccountNotWritable));
        let foreign = Acc { owner: [0x42; 32], ..cfg_acc(base_config()) };
        assert_eq!(with(admin_acc(), foreign), err(SijkaError::InvalidConfigAccount));
        let mut bad_disc = base_config();
        bad_disc[0] ^= 1;
        assert_eq!(with(admin_acc(), cfg_acc(bad_disc)), err(SijkaError::InvalidConfigAccount));
        let mut bad_version = base_config();
        bad_version[8] = 2;
        assert_eq!(with(admin_acc(), cfg_acc(bad_version)), err(SijkaError::InvalidConfigAccount));
        assert_eq!(with(admin_acc(), cfg_acc(vec![0u8; CONFIG_LEN - 1])), err(SijkaError::InvalidConfigAccount));
    }

    // ---------------------------------------------------------- tag 1 ----

    fn spl_mint() -> Vec<u8> {
        let mut d = vec![0u8; 82];
        d[36..44].copy_from_slice(&1_000_000_000_000_000u64.to_le_bytes());
        d[44] = 6;
        d[45] = 1;
        d
    }

    fn t22_mint(exts: &[(u16, u16)]) -> Vec<u8> {
        let mut d = spl_mint();
        d.resize(165, 0);
        d.push(1); // account type Mint
        for (ty, len) in exts {
            d.extend_from_slice(&ty.to_le_bytes());
            d.extend_from_slice(&len.to_le_bytes());
            d.extend(std::iter::repeat_n(0xAB, usize::from(*len)));
        }
        d
    }

    fn sharing_config_data(mint: &Pubkey, fee_inbox: &Pubkey, bump: u8) -> Vec<u8> {
        let mut d = vec![0u8; 150];
        d[0..8].copy_from_slice(&SHARING_CONFIG_DISC);
        d[8] = bump;
        d[9] = 2;
        d[10] = 1;
        d[11..43].copy_from_slice(mint);
        d[43..75].copy_from_slice(&[0x33; 32]);
        d[75] = 1;
        d[76..80].copy_from_slice(&1u32.to_le_bytes());
        d[80..112].copy_from_slice(fee_inbox);
        d[112..114].copy_from_slice(&10_000u16.to_le_bytes());
        d
    }

    fn sharing_pda(mint: &Pubkey) -> (Pubkey, u8) {
        pda::find(&[SEED_PUMP_SHARING_CONFIG, mint], &PUMP_FEES_PROGRAM).unwrap()
    }

    fn mint_accounts(mint_owner: Pubkey, mint_data: Vec<u8>) -> Vec<Acc> {
        let (sc, bump) = sharing_pda(&MINT);
        vec![
            admin_acc(),
            cfg_acc(base_config()),
            Acc::new(MINT, mint_owner, mint_data),
            Acc::new(sc, PUMP_FEES_PROGRAM, sharing_config_data(&MINT, &pdas().fee_inbox.key, bump)),
        ]
    }

    #[test]
    fn set_token_mint_records_the_coin_once() {
        for (owner, data) in
            [(SPL_TOKEN_PROGRAM_ID, spl_mint()), (TOKEN_2022_PROGRAM_ID, t22_mint(&[(18, 64), (19, 170)]))]
        {
            let (r, mut t) = run(set_token_mint_at, &mint_accounts(owner, data.clone()), &[1]);
            assert_eq!(r, Ok(()));
            let b = data_of(&mut t, 1);
            let mut expected = base_config();
            {
                let mut m = ConfigMut::new(&mut expected).unwrap();
                m.set_token_mint(&MINT);
                m.set_token_program(&owner);
                m.set_token_decimals(6);
                m.set_buyback_token(&pda::find_ata(&pdas().buyback_authority.key, &owner, &MINT).unwrap());
                m.set_token_mint_set_ts(NOW.ts);
                m.set_last_admin_action_ts(NOW.ts);
            }
            assert_eq!(b, expected);
            // A repeat fails (TA-10), whatever the mint.
            let mut again = mint_accounts(owner, data);
            again[1].data = b;
            assert_eq!(res(set_token_mint_at, &again, &[1]), err(SijkaError::TokenMintAlreadySet));
        }
        assert_admin_rules(set_token_mint_at, &mint_accounts(SPL_TOKEN_PROGRAM_ID, spl_mint())[2..], &[1]);
    }

    #[test]
    fn set_token_mint_rejects_unsafe_mints() {
        let mut cases: Vec<(Pubkey, Vec<u8>)> = vec![([0x42; 32], spl_mint())];
        for (off, v) in [(0usize, 1u8), (46, 1), (45, 0)] {
            // mint authority Some, freeze authority Some, not initialized
            let mut d = spl_mint();
            d[off] = v;
            cases.push((SPL_TOKEN_PROGRAM_ID, d.clone()));
            let mut t = t22_mint(&[(18, 64)]);
            t[off] = v;
            cases.push((TOKEN_2022_PROGRAM_ID, t));
        }
        let mut d = spl_mint();
        d.push(0); // 83 bytes
        cases.push((SPL_TOKEN_PROGRAM_ID, d));
        // Token-2022 extensions other than 18 / 19 (TA-10, U-26).
        for ext in [1u16, 3, 6, 9, 12, 14, 26] {
            cases.push((TOKEN_2022_PROGRAM_ID, t22_mint(&[(18, 64), (ext, 8), (19, 170)])));
        }
        let mut d = t22_mint(&[(18, 64)]);
        d[165] = 2; // account type Account
        cases.push((TOKEN_2022_PROGRAM_ID, d));
        cases.push((TOKEN_2022_PROGRAM_ID, t22_mint(&[])[..165].to_vec())); // no account type
        cases.push((TOKEN_2022_PROGRAM_ID, spl_mint())); // 82-byte Token-2022 mint
        let mut d = t22_mint(&[(18, 64)]);
        d.truncate(d.len() - 1); // record past the end
        cases.push((TOKEN_2022_PROGRAM_ID, d));
        let mut d = t22_mint(&[(18, 64)]);
        d.extend_from_slice(&[19, 0]); // partial header
        cases.push((TOKEN_2022_PROGRAM_ID, d));
        for (i, (owner, data)) in cases.into_iter().enumerate() {
            let r = res(set_token_mint_at, &mint_accounts(owner, data), &[1]);
            assert_eq!(r, err(SijkaError::InvalidTokenMint), "case {i}");
        }
    }

    #[test]
    fn mint_tlv_walk() {
        assert_eq!(check_mint(&TOKEN_2022_PROGRAM_ID, &t22_mint(&[(18, 64), (19, 170)])), Ok(6));
        assert_eq!(check_mint(&TOKEN_2022_PROGRAM_ID, &t22_mint(&[(19, 0)])), Ok(6));
        assert_eq!(check_mint(&TOKEN_2022_PROGRAM_ID, &t22_mint(&[])), Ok(6));
        // A zero type ends the list; the rest is not parsed.
        let mut d = t22_mint(&[(18, 64)]);
        d.extend_from_slice(&[0, 0, 0, 0, 0xFF, 0xFF]);
        assert_eq!(check_mint(&TOKEN_2022_PROGRAM_ID, &d), Ok(6));
        assert_eq!(check_mint(&SPL_TOKEN_PROGRAM_ID, &spl_mint()), Ok(6));
        assert_eq!(check_mint(&SYSTEM_PROGRAM_ID, &spl_mint()), Err(SijkaError::InvalidTokenMint));
        let mut d9 = spl_mint();
        d9[44] = 9;
        assert_eq!(check_mint(&SPL_TOKEN_PROGRAM_ID, &d9), Ok(9));
    }

    #[test]
    fn set_token_mint_requires_a_locked_full_share() {
        let fee_inbox = pdas().fee_inbox.key;
        let (_, bump) = sharing_pda(&MINT);
        let mutations: [fn(&mut Vec<u8>); 10] = [
            |d| d[0] ^= 1,                                            // discriminator
            |d| d[9] = 1,                                             // version
            |d| d[10] = 0,                                            // status Paused
            |d| d[11] ^= 1,                                           // other mint
            |d| d[75] = 0,                                            // admin not revoked
            |d| d[76..80].copy_from_slice(&2u32.to_le_bytes()),       // 2 shareholders
            |d| d[80] ^= 1,                                           // not fee_inbox
            |d| d[112..114].copy_from_slice(&9_999u16.to_le_bytes()), // 99.99%
            |d| d[8] = d[8].wrapping_sub(1),                          // bump → other address
            |d| d.truncate(113),                                      // record cut
        ];
        for (i, m) in mutations.iter().enumerate() {
            let mut a = mint_accounts(SPL_TOKEN_PROGRAM_ID, spl_mint());
            let mut d = sharing_config_data(&MINT, &fee_inbox, bump);
            m(&mut d);
            a[3].data = d;
            assert_eq!(res(set_token_mint_at, &a, &[1]), err(SijkaError::InvalidSharingConfig), "case {i}");
        }
        let mut a = mint_accounts(SPL_TOKEN_PROGRAM_ID, spl_mint());
        a[3].owner = PUMP_PROGRAM;
        assert_eq!(res(set_token_mint_at, &a, &[1]), err(SijkaError::InvalidSharingConfig));
        let mut a = mint_accounts(SPL_TOKEN_PROGRAM_ID, spl_mint());
        a[3].key = [0x42; 32];
        assert_eq!(res(set_token_mint_at, &a, &[1]), err(SijkaError::InvalidSharingConfig));
    }

    // ---------------------------------------------------------- tag 2 ----

    fn trader_pda() -> (Pubkey, u8) {
        pda::find(&[SEED_PHOENIX_TRADER, &pdas().phx_authority.key, &[0, 0]], &PHOENIX_PROGRAM_ID).unwrap()
    }

    fn trader_account_data(key: &Pubkey, authority: &Pubkey) -> Vec<u8> {
        let mut d = vec![0u8; TRADER_ACCOUNT_LEN];
        let mut put = |off: usize, k: &Pubkey| d[off..off + 32].copy_from_slice(k);
        put(trl::TRADER_KEY, key);
        put(trl::AUTHORITY, authority);
        put(trl::POSITION_AUTHORITY, authority);
        put(trl::FUNDING_KEY, &[0x44; 32]);
        d[0..8].copy_from_slice(&DISC_TRADER);
        d[trl::FLAGS..trl::FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());
        d[trl::MAX_POSITIONS..trl::MAX_POSITIONS + 4].copy_from_slice(&64u32.to_le_bytes());
        d[trl::PREFERENCE_BITS..trl::PREFERENCE_BITS + 4].copy_from_slice(&0u32.to_le_bytes());
        d[trl::CAP..trl::CAP + 8].copy_from_slice(&128u64.to_le_bytes());
        d
    }

    fn register_accounts(existing: bool) -> Vec<Acc> {
        let p = pdas();
        let (tk, _) = trader_pda();
        let trader = if existing {
            Acc::new(tk, PHOENIX_PROGRAM_ID, trader_account_data(&tk, &p.phx_authority.key)).w()
        } else {
            Acc::new(tk, SYSTEM_PROGRAM_ID, vec![]).w().empty()
        };
        vec![
            admin_acc(),
            cfg_acc(base_config()),
            Acc::new(p.phx_authority.key, SYSTEM_PROGRAM_ID, vec![]).empty(),
            Acc { lamports: 30_000_000, ..Acc::new(p.rent_payer.key, SYSTEM_PROGRAM_ID, vec![]).w() },
            Acc::new(PHOENIX_PROGRAM_ID, NATIVE_LOADER, vec![]).x(),
            Acc::new(PHOENIX_LOG_AUTHORITY, SYSTEM_PROGRAM_ID, vec![]).empty(),
            gc_acc(),
            trader,
            Acc::new(SYSTEM_PROGRAM_ID, NATIVE_LOADER, vec![]).x(),
        ]
    }

    #[test]
    fn register_account_checks() {
        let d = [2u8, trader_pda().1];
        let cases: [SlotCase; 11] = [
            (2, |a| a.key = [0x42; 32], SijkaError::InvalidPda),
            (3, |a| a.key = [0x42; 32], SijkaError::InvalidPda),
            (3, |a| a.writable = false, SijkaError::AccountNotWritable),
            (3, |a| a.data = vec![0], SijkaError::InvalidExternalAccount),
            (3, |a| a.owner = PHOENIX_PROGRAM_ID, SijkaError::InvalidExternalAccount),
            (4, |a| a.exec = false, SijkaError::InvalidProgramId),
            (4, |a| a.key = HAWKEYE_PROGRAM_ID, SijkaError::InvalidProgramId),
            (5, |a| a.key = [0x42; 32], SijkaError::InvalidExternalAccount),
            (8, |a| a.key = [0x42; 32], SijkaError::InvalidProgramId),
            (7, |a| a.writable = false, SijkaError::AccountNotWritable),
            // Foreign account at the trader slot (TA-6).
            (7, |a| a.key = [0x42; 32], SijkaError::InvalidPhoenixTraderPda),
        ];
        for (i, (slot, m, e)) in cases.iter().enumerate() {
            let mut a = register_accounts(true);
            m(&mut a[*slot]);
            assert_eq!(res(register_phoenix_trader_at, &a, &d), err(*e), "case {i}");
        }
        // Wrong bump (TA-6).
        let bad_bump = [2u8, d[1].wrapping_sub(1)];
        let r = res(register_phoenix_trader_at, &register_accounts(true), &bad_bump);
        assert_eq!(r, err(SijkaError::InvalidPhoenixTraderPda));
        // Already registered.
        let mut done = base_config();
        ConfigMut::new(&mut done).unwrap().set_phoenix_trader(&[0x9E; 32]);
        let mut a = register_accounts(true);
        a[1].data = done;
        assert_eq!(res(register_phoenix_trader_at, &a, &d), err(SijkaError::TraderAlreadyRegistered));
        assert_admin_rules(register_phoenix_trader_at, &register_accounts(true)[2..], &d);
    }

    #[test]
    fn register_front_run_path() {
        // Trader created directly by someone else with prefs 0 (TA-7): accepted,
        // `trader_registered_by_program = 0`, the actual prefs recorded.
        let (tk, bump) = trader_pda();
        let (r, mut t) = run(register_phoenix_trader_at, &register_accounts(true), &[2, bump]);
        assert_eq!(r, Ok(()));
        let mut expected = base_config();
        {
            let mut m = ConfigMut::new(&mut expected).unwrap();
            m.set_phoenix_trader(&tk);
            m.set_phoenix_trader_bump(bump);
            m.set_trader_preference_bits(0);
            m.set_trader_max_positions(64);
            m.set_trader_registered_by_program(0);
            m.set_trader_registered_ts(NOW.ts);
            m.set_last_admin_action_ts(NOW.ts);
        }
        assert_eq!(data_of(&mut t, 1), expected);
        // A trader at our PDA with another authority is never accepted.
        let mut a = register_accounts(true);
        a[7].data = trader_account_data(&tk, &[0x42; 32]);
        assert_eq!(res(register_phoenix_trader_at, &a, &[2, bump]), err(SijkaError::InvalidPhoenixTraderAccount));
        let mut a = register_accounts(true);
        a[7].owner = [0x42; 32];
        assert_eq!(res(register_phoenix_trader_at, &a, &[2, bump]), err(SijkaError::InvalidPhoenixTraderAccount));
    }

    #[test]
    fn register_cpi_path_reaches_the_rent_check() {
        let r = res(register_phoenix_trader_at, &register_accounts(false), &[2, trader_pda().1]);
        assert!(reached_rent(r), "{r:?}");
        // GlobalConfig (§5.0.5) is checked on both paths.
        for m in [|a: &mut Acc| a.key = [0x42; 32], |a: &mut Acc| a.owner = [0x42; 32], |a: &mut Acc| a.data[0] ^= 1] {
            let mut a = register_accounts(true);
            m(&mut a[6]);
            let r = res(register_phoenix_trader_at, &a, &[2, trader_pda().1]);
            assert_eq!(r, err(SijkaError::InvalidPhoenixGlobalConfig));
        }
    }

    #[test]
    fn register_rent_requirement() {
        // SPEC §5.1.2 reference numbers: rent(5360) + rent(0) at 5080 lamports
        // per byte, threshold 1.0.
        let t1 = 1.0f64.to_bits();
        let need = crate::util::math::rent_exempt_minimum_with(5080, t1, TRADER_ACCOUNT_LEN).unwrap()
            + crate::util::math::rent_exempt_minimum_with(5080, t1, 0).unwrap();
        assert_eq!(need, 27_879_040 + 650_240);
    }

    #[test]
    fn trader_header_rules() {
        let (tk, _) = trader_pda();
        let a = pdas().phx_authority.key;
        let good = trader_account_data(&tk, &a);
        let h = check_trader_header(&good, &tk, &a).unwrap();
        assert_eq!((h.max_positions, h.preference_bits, h.funding_key), (64, 0, [0x44; 32]));
        for off in
            [0usize, trl::TRADER_KEY, trl::AUTHORITY, trl::POSITION_AUTHORITY, trl::PDA_INDEX, trl::SUBACCOUNT_INDEX]
        {
            let mut d = good.clone();
            d[off] ^= 1;
            assert_eq!(check_trader_header(&d, &tk, &a).err(), Some(SijkaError::InvalidPhoenixTraderAccount), "@{off}");
        }
        assert_eq!(check_trader_header(&good[..239], &tk, &a).err(), Some(SijkaError::InvalidPhoenixTraderAccount));
    }

    // ---------------------------------------------------------- tag 3 ----

    fn trader_data(k: &Pubkey) -> Vec<u8> {
        let mut d = vec![3u8];
        d.extend_from_slice(k);
        d
    }

    #[test]
    fn set_trader_changes_the_trading_key() {
        // A new key, the same key again, 0 (trading off), then back.
        let mut cfg = base_config();
        for new in [TRADER, TRADER, ZERO_KEY, [0x77u8; 32], ADMIN] {
            let (r, mut t) = run(set_trader_at, &[admin_acc(), cfg_acc(cfg.clone())], &trader_data(&new));
            assert_eq!(r, Ok(()));
            // Exactly `trader` and `last_admin_action_ts` changed.
            let mut expected = cfg.clone();
            {
                let mut m = ConfigMut::new(&mut expected).unwrap();
                m.set_trader(&new);
                m.set_last_admin_action_ts(NOW.ts);
            }
            let after = data_of(&mut t, 1);
            assert_eq!(after, expected);
            cfg = after;
        }
        // Allowed in recovery mode (the key closes positions, SPEC §5.6.5).
        let mut rec = base_config();
        ConfigMut::new(&mut rec).unwrap().set_recovery_mode(1);
        assert_eq!(res(set_trader_at, &[admin_acc(), cfg_acc(rec)], &trader_data(&TRADER)), Ok(()));
    }

    /// TU-T2: each of the nine program PDAs is refused; 0 and any other key pass.
    #[test]
    fn set_trader_rejects_program_pdas_and_non_admins() {
        for k in pdas().keys() {
            let r = res(set_trader_at, &[admin_acc(), cfg_acc(base_config())], &trader_data(k));
            assert_eq!(r, err(SijkaError::InvalidParams), "{k:?}");
        }
        assert_eq!(pdas().keys().len(), 9);
        let c = base_config();
        let v = Config::new(&c).unwrap();
        let config_key = pdas().config.key;
        assert_eq!(check_role_key(&ZERO_KEY, &v, &config_key), Ok(()));
        assert_eq!(check_role_key(&TRADER, &v, &config_key), Ok(()));
        assert_eq!(check_role_key(&config_key, &v, &config_key), Err(SijkaError::InvalidParams));
        assert_eq!(check_role_key(&pdas().phx_authority.key, &v, &config_key), Err(SijkaError::InvalidParams));
        assert_admin_rules(set_trader_at, &[], &trader_data(&[0x77; 32]));
        // Nothing else is read: config must be writable, the shape exact.
        let mut ro = cfg_acc(base_config());
        ro.writable = false;
        assert_eq!(res(set_trader_at, &[admin_acc(), ro], &trader_data(&TRADER)), err(SijkaError::AccountNotWritable));
    }

    // --------------------------------------------------------- tag 28 ----

    const KEEPER: Pubkey = [0x4B; 32];

    fn keeper_data(k: &Pubkey) -> Vec<u8> {
        let mut d = vec![28u8];
        d.extend_from_slice(k);
        d
    }

    /// SPEC §5.1.10: the admin sets the keeper at once; 0 (swaps off) and back.
    #[test]
    fn set_keeper_changes_the_keeper_key() {
        let mut cfg = base_config();
        assert_eq!(Config::new(&cfg).unwrap().keeper(), &ZERO_KEY, "no keeper after initialize");
        for new in [KEEPER, KEEPER, ZERO_KEY, [0x77u8; 32]] {
            let (r, mut t) = run(set_keeper_at, &[admin_acc(), cfg_acc(cfg.clone())], &keeper_data(&new));
            assert_eq!(r, Ok(()));
            // Exactly `keeper` (@48) and `last_admin_action_ts` changed.
            let mut expected = cfg.clone();
            {
                let mut m = ConfigMut::new(&mut expected).unwrap();
                m.set_keeper(&new);
                m.set_last_admin_action_ts(NOW.ts);
            }
            let after = data_of(&mut t, 1);
            assert_eq!(after, expected);
            assert_eq!(&after[48..80], &new);
            cfg = after;
        }
        // Allowed in recovery mode (tag 43 keeps spending the buyback).
        let mut rec = base_config();
        ConfigMut::new(&mut rec).unwrap().set_recovery_mode(1);
        assert_eq!(res(set_keeper_at, &[admin_acc(), cfg_acc(rec)], &keeper_data(&KEEPER)), Ok(()));
        // The trading key is untouched.
        let (_, mut t) = run(set_keeper_at, &[admin_acc(), cfg_acc(base_config())], &keeper_data(&KEEPER));
        assert_eq!(Config::new(&data_of(&mut t, 1)).unwrap().trader(), Config::new(&base_config()).unwrap().trader());
    }

    /// Each of the nine program PDAs is refused; only the admin may call.
    #[test]
    fn set_keeper_rejects_program_pdas_and_non_admins() {
        for k in pdas().keys() {
            let r = res(set_keeper_at, &[admin_acc(), cfg_acc(base_config())], &keeper_data(k));
            assert_eq!(r, err(SijkaError::InvalidParams), "{k:?}");
        }
        assert_admin_rules(set_keeper_at, &[], &keeper_data(&KEEPER));
        // The trading key signing tag 28 is not the admin.
        let trader = Acc::new(TRADER, SYSTEM_PROGRAM_ID, vec![]).s();
        let r = res(set_keeper_at, &[trader, cfg_acc(base_config())], &keeper_data(&KEEPER));
        assert_eq!(r, err(SijkaError::Unauthorized));
    }

    // ---------------------------------------------------- shape first ----

    #[test]
    fn handlers_check_shape_first() {
        let cfg = cfg_acc(base_config());
        let three = [admin_acc(), cfg.clone(), cfg.clone()];
        assert_eq!(res(set_keeper_at, &three, &keeper_data(&KEEPER)), err(SijkaError::InvalidAccountCount));
        let two = [admin_acc(), cfg.clone()];
        assert_eq!(res(set_keeper_at, &two, &[28]), err(SijkaError::InvalidInstructionData));
        let mut long = keeper_data(&KEEPER);
        long.push(0);
        assert_eq!(res(set_keeper_at, &two, &long), err(SijkaError::InvalidInstructionData));
        let five = &init_accounts()[..5];
        assert_eq!(res(initialize_at, five, &good_init_data()), err(SijkaError::InvalidAccountCount));
        // The pre-v2 initialize length (297) is refused.
        assert_eq!(res(initialize_at, &init_accounts(), &[0u8; 297]), err(SijkaError::InvalidInstructionData));
        assert_eq!(res(set_trader_at, &three, &trader_data(&TRADER)), err(SijkaError::InvalidAccountCount));
        let two = [admin_acc(), cfg.clone()];
        assert_eq!(res(set_trader_at, &two, &[3]), err(SijkaError::InvalidInstructionData));
        let mut long = trader_data(&TRADER);
        long.push(0);
        assert_eq!(res(set_trader_at, &two, &long), err(SijkaError::InvalidInstructionData));
    }
}
