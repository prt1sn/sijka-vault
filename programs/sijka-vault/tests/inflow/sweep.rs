// Copyright (c) 2026 prt1sn. All rights reserved.
//! Sweeps (tags 22, 23; SPEC §5.3.6; TC-30): any USDC account of `fee_inbox`
//! (22) or `swap_authority` (23) is emptied into `vault_usdc`; foreign
//! authority, wrong mint, delegates, empty sources and wrong vaults refused.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::harness::*;

pub fn sweep_ix(env: &Env, tag: u8, source: Pubkey) -> Instruction {
    let authority = if tag == 22 { env.k.fee_inbox } else { env.k.swap_authority };
    Instruction {
        program_id: env.k.program,
        accounts: vec![
            AccountMeta::new(env.k.config, false),
            AccountMeta::new_readonly(authority, false),
            AccountMeta::new(source, false),
            AccountMeta::new(env.k.vault_usdc, false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data: vec![tag],
    }
}

pub fn sweep(env: &mut Env, tag: u8, source: Pubkey) -> TxResult {
    let ix = sweep_ix(env, tag, source);
    env.send(vec![ix], &[])
}

fn env_with_fee_inbox() -> Option<Env> {
    let mut env = Env::new(Opts { usdc_pair: true, ..Opts::default() })?;
    let r = env.rent(0);
    let fi = env.k.fee_inbox;
    env.transfer_lamports(&fi, r);
    Some(env)
}

#[test]
fn tc30_sweep_fee_inbox_ata() {
    let Some(mut env) = env_with_fee_inbox() else { return };
    // The USDC pair: pump pays fees to ATA(fee_inbox, USDC).
    let (fi, usdc) = (env.k.fee_inbox, env.k.usdc_mint);
    let src = env.create_ata(&fi, &usdc);
    env.mint_usdc(src, 7_000_000);
    let m = expect_ok(sweep(&mut env, 22, src));
    assert_eq!(env.token_amount(&src), 0);
    assert_eq!(env.token_amount(&env.k.vault_usdc), 7_000_000);
    assert_eq!(env.cfg("cum_fee_usdc_swept"), 7_000_000);
    assert_eq!(env.cfg("cum_inflow_usdc"), 0, "I only at tag 21");
    let e = event(&m.logs, "SJKEVSFU");
    assert_eq!(e.u("amount"), 7_000_000);
    let (off, _) = abi().ev_field("SJKEVSFU", "source");
    assert_eq!(key_at(&e.d, off), src);
    // The ATA is kept (never closed) and can be swept again.
    assert!(env.account(&src).is_some());
    env.mint_usdc(src, 1);
    expect_ok(sweep(&mut env, 22, src));
    assert_eq!(env.cfg("cum_fee_usdc_swept"), 7_000_001);
    // Empty: SweepNothing.
    expect_err(sweep(&mut env, 22, src), "SweepNothing");
}

#[test]
fn tc30_non_canonical_fee_inbox_account() {
    let Some(mut env) = env_with_fee_inbox() else { return };
    let (fi, usdc) = (env.k.fee_inbox, env.k.usdc_mint);
    let src = Pubkey::new_from_array([0xD1; 32]);
    env.set_token(src, usdc, fi, 0, false);
    env.mint_usdc(src, 3_000_000);
    expect_ok(sweep(&mut env, 22, src));
    assert_eq!(env.token_amount(&env.k.vault_usdc), 3_000_000);
}

#[test]
fn tc30_refused_sources() {
    let Some(mut env) = env_with_fee_inbox() else { return };
    let (fi, usdc) = (env.k.fee_inbox, env.k.usdc_mint);
    let phusd = env.k.phusd_mint;
    let att = env.attacker_usdc;
    env.mint_usdc(att, 1_000_000);
    // Foreign authority.
    expect_err(sweep(&mut env, 22, att), "InvalidTokenAccount");
    // Wrong mint.
    let wrong_mint = Pubkey::new_from_array([0xD2; 32]);
    env.set_token(wrong_mint, phusd, fi, 5, false);
    expect_err(sweep(&mut env, 22, wrong_mint), "InvalidTokenAccount");
    // A delegate or a close authority on the source.
    let delegated = Pubkey::new_from_array([0xD3; 32]);
    env.set_token(delegated, usdc, fi, 5, false);
    env.patch(&delegated, 72, &1u32.to_le_bytes());
    expect_err(sweep(&mut env, 22, delegated), "InvalidTokenAccount");
    let closable = Pubkey::new_from_array([0xD4; 32]);
    env.set_token(closable, usdc, fi, 5, false);
    env.patch(&closable, 129, &1u32.to_le_bytes());
    expect_err(sweep(&mut env, 22, closable), "InvalidTokenAccount");
    // Frozen.
    let frozen = Pubkey::new_from_array([0xD5; 32]);
    env.set_token(frozen, usdc, fi, 5, false);
    env.patch(&frozen, 108, &[2]);
    expect_err(sweep(&mut env, 22, frozen), "InvalidTokenAccount");
    // Token-2022 owned.
    let t22 = Pubkey::new_from_array([0xD6; 32]);
    env.set_token(t22, usdc, fi, 5, false);
    let mut a = env.account(&t22).unwrap();
    a.owner = token_2022();
    env.set(t22, a);
    expect_err(sweep(&mut env, 22, t22), "InvalidTokenAccount");
    // A swap_authority account through tag 22 and a fee_inbox account
    // through tag 23.
    let su = env.k.swap_usdc;
    env.mint_usdc(su, 5);
    expect_err(sweep(&mut env, 22, su), "InvalidTokenAccount");
    let fa = env.create_ata(&fi, &usdc);
    env.mint_usdc(fa, 5);
    expect_err(sweep(&mut env, 23, fa), "InvalidTokenAccount");
    // vault_usdc as the source.
    let vault = env.k.vault_usdc;
    env.mint_usdc(vault, 5);
    expect_err(sweep(&mut env, 22, vault), "InvalidTokenAccount");
    expect_err(sweep(&mut env, 23, vault), "InvalidTokenAccount");
}

#[test]
fn tc30_wrong_accounts() {
    let Some(mut env) = env_with_fee_inbox() else { return };
    let (fi, usdc) = (env.k.fee_inbox, env.k.usdc_mint);
    let src = env.create_ata(&fi, &usdc);
    env.mint_usdc(src, 5);
    let other_vault = Pubkey::new_from_array([0xD7; 32]);
    env.set_token(other_vault, usdc, env.k.phx_authority, 0, false);
    let cases: Vec<(usize, AccountMeta, &str)> = vec![
        (1, AccountMeta::new_readonly(env.attacker.pubkey(), false), "InvalidPda"),
        (3, AccountMeta::new(other_vault, false), "InvalidPda"),
        (3, AccountMeta::new(env.attacker_usdc, false), "InvalidPda"),
        (4, AccountMeta::new_readonly(token_2022(), false), "InvalidProgramId"),
        (2, AccountMeta::new_readonly(src, false), "AccountNotWritable"),
    ];
    for (i, meta, err) in cases {
        let mut ix = sweep_ix(&env, 22, src);
        ix.accounts[i] = meta;
        expect_err(env.send(vec![ix], &[]), err);
    }
    // Tag 23 needs swap_authority read-only.
    let su = env.k.swap_usdc;
    env.mint_usdc(su, 5);
    let mut ix = sweep_ix(&env, 23, su);
    ix.accounts[1] = AccountMeta::new(env.k.swap_authority, false);
    expect_err(env.send(vec![ix], &[]), "AccountMustBeReadonly");
    assert_eq!(env.token_amount(&src), 5);
}

#[test]
fn tc30_sweep_swap_usdc_donation() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    let su = env.k.swap_usdc;
    env.mint_usdc(su, 2_500_000);
    let m = expect_ok(sweep(&mut env, 23, su));
    assert_eq!(env.token_amount(&su), 0);
    assert_eq!(env.token_amount(&env.k.vault_usdc), 2_500_000);
    assert_eq!(env.cfg("cum_swap_usdc_swept"), 2_500_000);
    assert_eq!(event(&m.logs, "SJKEVSSU").u("amount"), 2_500_000);
    expect_err(sweep(&mut env, 23, su), "SweepNothing");
    // Any other USDC account of swap_authority is swept too.
    let (sa, usdc) = (env.k.swap_authority, env.k.usdc_mint);
    let extra = Pubkey::new_from_array([0xD8; 32]);
    env.set_token(extra, usdc, sa, 0, false);
    env.mint_usdc(extra, 11);
    expect_ok(sweep(&mut env, 23, extra));
    assert_eq!(env.cfg("cum_swap_usdc_swept"), 2_500_011);
}

#[test]
fn sweeps_work_in_recovery_and_ignore_the_retired_pause_byte() {
    let Some(mut env) = env_with_fee_inbox() else { return };
    let (fi, usdc) = (env.k.fee_inbox, env.k.usdc_mint);
    let src = env.create_ata(&fi, &usdc);
    env.mint_usdc(src, 9);
    env.set_cfg("_reserved10", 3); // the former inflow_pause_mask (SPEC v4: no pause)
    env.set_cfg("recovery_mode", 1);
    expect_ok(sweep(&mut env, 22, src));
    let su = env.k.swap_usdc;
    env.mint_usdc(su, 4);
    expect_ok(sweep(&mut env, 23, su));
    assert_eq!(env.token_amount(&env.k.vault_usdc), 13);
}
