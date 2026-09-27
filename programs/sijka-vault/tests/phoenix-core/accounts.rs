// Copyright (c) 2026 prt1sn. All rights reserved.
//! Deny-by-default account checks of tags 21, 30, 31, 32 (TC-26, TH-9,
//! INV-7): every slot replaced by a plausible wrong account, a writable slot
//! passed readonly, arena lists and counts. Each must fail with its SPEC
//! error before any CPI (no `invoke [2]` in the logs) and leave no trace.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::harness::*;

fn no_cpi(logs: &[String]) -> bool {
    !logs.iter().any(|l| l.contains(" invoke [2]"))
}

fn run_cases(env: &mut Env, name: &str, base: &Instruction, cases: Vec<(usize, Pubkey, &'static str)>) {
    for (slot, key, e) in cases {
        let mut ix = base.clone();
        ix.accounts[slot].pubkey = key;
        let label = format!("{name} slot #{slot} -> {key}");
        let f = expect_err(env.send1(ix, S_PAYER), e, &label);
        assert!(no_cpi(&f.meta.logs), "{label}: a CPI ran before the check\n{}", f.meta.logs.join("\n"));
    }
}

fn run_readonly(env: &mut Env, name: &str, base: &Instruction, slots: &[usize], e: &'static str) {
    for slot in slots {
        let mut ix = base.clone();
        let k = ix.accounts[*slot].pubkey;
        ix.accounts[*slot] = AccountMeta::new_readonly(k, false);
        let label = format!("{name} slot #{slot} readonly");
        let f = expect_err(env.send1(ix, S_PAYER), e, &label);
        assert!(no_cpi(&f.meta.logs), "{label}: a CPI ran before the check");
    }
}

fn run_tails(env: &mut Env, name: &str, base: &Instruction, gti_slot: usize, count_off: usize) {
    // GTI[0] replaced by ATB[0]; ATB[0] replaced by a random account.
    let atb0 = base.accounts[gti_slot + 1].pubkey;
    run_cases(env, name, base, vec![(gti_slot, atb0, "InvalidArenaAccounts")]);
    run_cases(env, name, base, vec![(gti_slot + 1, Pubkey::new_unique(), "InvalidArenaAccounts")]);
    // One extra account; g = 0; g = 9.
    let mut ix = base.clone();
    ix.accounts.push(AccountMeta::new_readonly(SYSTEM_PROGRAM, false));
    expect_err(env.send1(ix, S_PAYER), "InvalidAccountCount", &format!("{name} extra account"));
    let mut ix = base.clone();
    ix.data[count_off] = 0;
    expect_err(env.send1(ix, S_PAYER), "InvalidArenaAccounts", &format!("{name} gti_count 0"));
    let mut ix = base.clone();
    ix.data[count_off] = 9;
    expect_err(env.send1(ix, S_PAYER), "InvalidArenaAccounts", &format!("{name} gti_count 9"));
    let mut ix = base.clone();
    ix.data.push(0);
    expect_err(env.send1(ix, S_PAYER), "InvalidInstructionData", &format!("{name} data + 1"));
}

#[test]
fn deposit_account_substitutions() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(0);
    let vu = env.vault_usdc();
    env.mint_usdc(&vu, 50_000_000);
    let base = env.deposit_ix(0);
    let taker0 = env.ctx.actor_trader("taker0");
    let cases = vec![
        (1usize, env.pdas.rent_payer.0, "InvalidPda"),
        (2, env.escrow_usdc(), "InvalidPda"),
        (3, env.vault_usdc(), "InvalidPda"),
        (4, env.fx.phusd, "InvalidExternalAccount"),
        (5, env.fx.usdc, "InvalidPhoenixGlobalConfig"),
        (6, PHOENIX, "InvalidProgramId"),
        (7, Pubkey::new_unique(), "InvalidEmberAccount"),
        (8, Pubkey::new_unique(), "InvalidEmberAccount"),
        (9, EMBER, "InvalidProgramId"),
        (10, Pubkey::new_unique(), "InvalidExternalAccount"),
        (11, Pubkey::new_unique(), "InvalidPhoenixGlobalConfig"),
        (12, taker0, "InvalidPhoenixTraderAccount"),
        (13, EMBER_VAULT, "InvalidPhoenixGlobalConfig"),
        (14, TOKEN_2022, "InvalidProgramId"),
    ];
    run_cases(&mut env, "deposit", &base, cases);
    run_readonly(&mut env, "deposit", &base, &[2, 3, 8], "AccountNotWritable");
    run_tails(&mut env, "deposit", &base, 15, 1);
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), 0);
    assert_eq!(env.token_amount(&vu), 50_000_000);
    ok(env.send1(base, S_PAYER), "the unmodified deposit");
}

#[test]
fn harvest_account_substitutions() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    env.gift(30_000_000);
    env.pass_t_min();
    let base = env.harvest_ix();
    let taker0 = env.ctx.actor_trader("taker0");
    let book = env.market_book("SOL");
    let cases = vec![
        (1usize, env.pdas.rent_payer.0, "InvalidPda"),
        (2, HAWKEYE, "InvalidProgramId"),
        (3, PHOENIX, "InvalidProgramId"),
        (4, PHOENIX, "InvalidProgramId"),
        (5, Pubkey::new_unique(), "InvalidExternalAccount"),
        (6, Pubkey::new_unique(), "InvalidPhoenixGlobalConfig"),
        (7, taker0, "InvalidPhoenixTraderAccount"),
        (8, book, "InvalidPerpAssetMap"),
        (9, EMBER_VAULT, "InvalidPhoenixGlobalConfig"),
        (10, Pubkey::new_unique(), "InvalidPhoenixGlobalConfig"),
        (11, env.fx.phusd, "InvalidExternalAccount"),
        (12, env.fx.usdc, "InvalidPhoenixGlobalConfig"),
        (13, env.vault_usdc(), "InvalidPda"),
        (14, env.escrow_usdc(), "InvalidPda"),
        (15, Pubkey::new_unique(), "InvalidEmberAccount"),
        (16, Pubkey::new_unique(), "InvalidEmberAccount"),
        (17, TOKEN_2022, "InvalidProgramId"),
        (18, env.buyback_usdc(), "CreatorEscrowInvalid"),
        (19, env.escrow_usdc(), "BuybackAtaInvalid"),
    ];
    run_cases(&mut env, "harvest", &base, cases);
    run_readonly(&mut env, "harvest", &base, &[6, 7, 8, 9, 10, 12, 13, 14, 16, 18, 19], "AccountNotWritable");
    run_tails(&mut env, "harvest", &base, 20, 1);
    assert_eq!(env.cfg_u64("cum_payout_usdc"), 0);
    ok(env.send1(base, S_PAYER), "the unmodified harvest");
    assert!(env.cfg_u64("cum_payout_usdc") > 0);
}

#[test]
fn preview_and_pay_creator_account_substitutions() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let base = env.preview_ix();
    let taker0 = env.ctx.actor_trader("taker0");
    let cases = vec![
        (1usize, HAWKEYE, "InvalidProgramId"),
        (2, PHOENIX, "InvalidProgramId"),
        (3, Pubkey::new_unique(), "InvalidPhoenixGlobalConfig"),
        (4, taker0, "InvalidPhoenixTraderAccount"),
        (5, env.market_book("SOL"), "InvalidPerpAssetMap"),
        (6, Pubkey::new_unique(), "InvalidPhoenixGlobalConfig"),
        (7, env.escrow_usdc(), "BuybackAtaInvalid"),
    ];
    run_cases(&mut env, "harvest_preview", &base, cases);
    run_tails(&mut env, "harvest_preview", &base, 8, 1);

    let base = env.pay_creator_ix();
    let cases = vec![
        (1usize, env.pdas.phx_authority.0, "InvalidPda"),
        (2, env.buyback_usdc(), "CreatorEscrowInvalid"),
        (3, env.escrow_usdc(), "CreatorAtaInvalid"),
        (4, TOKEN_2022, "InvalidProgramId"),
    ];
    run_cases(&mut env, "pay_creator", &base, cases);
    run_readonly(&mut env, "pay_creator", &base, &[2, 3], "AccountNotWritable");
}

/// SPEC v3 §5.0.5 (§11.10: no delegate): tags 21, 30 and 31 accept our
/// trader account only while Phoenix names `phx_authority` both authority
/// (`@56`) and position authority (`@120`). A position authority set to the
/// trading key (what SPEC v2's delegate did) or to a stranger, or another
/// authority, is `InvalidPhoenixTraderAccount` before any CPI.
#[test]
fn trader_header_must_name_phx_authority_twice() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    env.gift(30_000_000);
    env.pass_t_min();
    let vu = env.vault_usdc();
    env.mint_usdc(&vu, 50_000_000);
    let t = env.pdas.trader.0;
    let original = env.data(&t);
    let cases = [
        (120usize, env.bot, "position authority = the trading key"),
        (120, env.attacker, "position authority = a stranger"),
        (56, env.bot, "authority = the trading key"),
    ];
    for (off, key, label) in cases {
        env.patch(&t, |d| d[off..off + 32].copy_from_slice(key.as_ref()));
        for (name, ix) in
            [("deposit_usdc", env.deposit_ix(0)), ("harvest", env.harvest_ix()), ("harvest_preview", env.preview_ix())]
        {
            let f = expect_err(env.send1(ix, S_PAYER), "InvalidPhoenixTraderAccount", &format!("{name}: {label}"));
            assert!(no_cpi(&f.meta.logs), "{name}: {label}: a CPI ran before the check");
        }
        env.patch(&t, |d| d.copy_from_slice(&original));
    }
    assert_eq!(env.cfg_u64("cum_payout_usdc"), 0);
    assert_eq!(env.token_amount(&vu), 50_000_000);
    ok(env.send1(env.preview_ix(), S_PAYER), "harvest_preview with the header restored");
}
