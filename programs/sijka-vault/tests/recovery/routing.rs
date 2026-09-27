// Copyright (c) 2026 prt1sn. All rights reserved.
//! Destinations of op 2 / op 3 / op 5 (SPEC §5.6.0): SPEC v4 (DECISIONS §23
//! item 2) has one route — the admin's ATAs and wallet fixed at `initialize`,
//! always (no `renounce_admin`, no route BUYBACK; even a zeroed admin changes
//! nothing) (TR-18, TR-19, TR-25 route part), and that no op touches the
//! buyback escrow or the unpaid creator share (TR-24, SPEC §5.6.6).

use sijka_vault::error::SijkaError;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

use crate::harness::*;
use crate::vault::*;

const USDC: u64 = 1_000_000;
const SOL: u64 = 1_000_000_000;

fn rent0(env: &VaultEnv) -> u64 {
    env.ctx.svm.minimum_balance_for_rent_exemption(0)
}

fn rcs(r: &TxResult) -> (u8, u8, u64, Pubkey, u64) {
    parse_rcs(&event(&assert_ok(r).logs, b"SJKEVRCS").expect("SJKEVRCS"))
}

/// TR-18 / TR-19, SOL pair: the recipient = the admin fixed at `initialize`
/// (wallet for SOL, ATAs for USDC / PhUSD) with its account checks; SPEC v4:
/// always, whatever `Config.admin` holds.
#[test]
fn tr18_tr19_recipient_route_always() {
    let Some(mut env) = VaultEnv::new(VaultOpts { deposit: 0, ..VaultOpts::default() }) else { return };
    env.latch_via_maintenance(false);
    let (admin, stranger) = (env.admin, env.stranger);
    let (er_usdc, bb_usdc, vu) = (env.er_usdc, env.buyback_usdc, env.vault_usdc);
    let p = env.p;
    let r0 = rent0(&env);

    // ---- op 3: SOL above rent on fee_inbox → the admin wallet.
    assert_err(&env.op_send_sol(admin), SijkaError::RecoveryNothing); // fee_inbox empty
    env.ctx.svm.airdrop(&p.fee_inbox, 3 * SOL).unwrap();
    let a0 = env.lamports(&admin);
    assert_err(&env.op_send_sol(stranger), SijkaError::RecoveryRecipientInvalid);
    assert_err(&env.op_send_sol(p.buyback_authority), SijkaError::RecoveryRecipientInvalid);
    let r = env.op_send_sol(admin);
    let (op, route, amount, dest, cum) = rcs(&r);
    assert_eq!((op, route, dest), (3, 0, admin));
    assert_eq!(amount, 3 * SOL - r0);
    assert_eq!(cum, amount);
    assert_eq!(env.lamports(&admin), a0 + amount);
    assert_eq!(env.lamports(&p.fee_inbox), r0, "fee_inbox keeps exactly its rent reserve");
    assert_err(&env.op_send_sol(admin), SijkaError::RecoveryNothing);
    assert_eq!(env.cfg(|c| c.cum_recovered_lamports()), amount);

    // ---- op 2: destination checks.
    env.ctx.mint_fake_usdc_to_token_account(vu, 50 * USDC);
    let stranger_usdc = ata(&stranger, &env.fx.usdc);
    assert_err(&env.op_send_token(2, stranger_usdc), SijkaError::RecoveryRecipientInvalid);
    assert_err(&env.op_send_token(2, bb_usdc), SijkaError::RecoveryRecipientInvalid);
    // Recipient ATA handed to another owner (SetAuthority): refused ...
    assert_ok(&env.send(ADMIN_SEED, vec![ix_token_set_owner(er_usdc, admin, stranger)]));
    assert_err(&env.op_send_token(2, er_usdc), SijkaError::RecoveryRecipientInvalid);
    assert_ok(&env.send(STRANGER_SEED, vec![ix_token_set_owner(er_usdc, stranger, admin)]));
    // ... closed (e.g. by a wallet cleaner): refused, re-created by anyone: ok.
    assert_ok(&env.send(ADMIN_SEED, vec![ix_token_close(er_usdc, admin, admin)]));
    assert!(env.ctx.svm.get_account(&er_usdc).is_none());
    assert_err(&env.op_send_token(2, er_usdc), SijkaError::RecoveryRecipientInvalid);
    let usdc_mint = env.fx.usdc;
    assert_ok(&env.send(STRANGER_SEED, vec![ix_create_ata(stranger, admin, usdc_mint)]));
    let r = env.op_send_token(2, er_usdc);
    let (op, route, amount, dest, _) = rcs(&r);
    assert_eq!((op, route, amount, dest), (2, 0, 50 * USDC, er_usdc));
    assert_eq!(env.amount(&er_usdc), 50 * USDC);

    // ---- SPEC v4: there is no BUYBACK route. A zeroed admin (the retired
    // renounce, injected bytes) changes nothing: USDC, PhUSD and SOL still
    // go only to the recipient fixed at `initialize`.
    let recipient_before = env.cfg(|c| (*c.emergency_recipient(), *c.emergency_recipient_usdc()));
    env.edit_cfg(|m| m.set_admin(&[0; 32]));
    env.ctx.mint_fake_usdc_to_token_account(vu, 20 * USDC);
    assert_err(&env.op_send_token(2, bb_usdc), SijkaError::RecoveryRecipientInvalid);
    let r = env.op_send_token(2, er_usdc);
    let (op, route, amount, dest, cum) = rcs(&r);
    assert_eq!((op, route, amount, dest, cum), (2, 0, 20 * USDC, er_usdc, 70 * USDC));
    assert_eq!(env.cfg(|c| c.cum_recovered_usdc()), 70 * USDC);
    // PhUSD as is to the recipient (op 5), or unwrapped (op 4) then op 2.
    let vp = env.vault_phusd;
    env.donate_phusd(vp, 4 * USDC);
    let er_phusd = env.er_phusd;
    let r = env.op_send_token(5, er_phusd);
    assert_eq!(rcs(&r).1, 0, "route RECIPIENT");
    env.donate_phusd(vp, 4 * USDC);
    let r = env.op_unwrap();
    let (_, route, u, _, _) = rcs(&r);
    assert_eq!(route, 0, "op 4 reports route 0");
    let r = env.op_send_token(2, er_usdc);
    assert_eq!(rcs(&r).2, u);
    // SOL: only the admin wallet, never the buyback SOL budget.
    env.ctx.svm.airdrop(&p.fee_inbox, SOL).unwrap();
    assert_err(&env.op_send_sol(p.buyback_authority), SijkaError::RecoveryRecipientInvalid);
    let r = env.op_send_sol(admin);
    let (op, route, amount, dest, _) = rcs(&r);
    assert_eq!((op, route, dest, amount), (3, 0, admin, SOL));
    // The recipient record is never rewritten.
    assert_eq!(env.cfg(|c| (*c.emergency_recipient(), *c.emergency_recipient_usdc())), recipient_before);
}

/// TR-19, USDC pair: op 3 pays the admin, always (SPEC v4: no route BUYBACK,
/// so no `RecoveryRouteUnavailable`, even with a zeroed admin).
#[test]
fn tr19_usdc_pair_sol_route() {
    let Some(mut env) = VaultEnv::new(VaultOpts { sol_pair: false, deposit: 0 }) else { return };
    env.latch_via_maintenance(false);
    let (admin, p) = (env.admin, env.p);
    env.ctx.svm.airdrop(&p.fee_inbox, 2 * SOL).unwrap();
    let a0 = env.lamports(&admin);
    assert_ok(&env.op_send_sol(admin));
    assert_eq!(env.lamports(&admin), a0 + 2 * SOL - rent0(&env));
    env.edit_cfg(|m| m.set_admin(&[0; 32]));
    env.ctx.svm.airdrop(&p.fee_inbox, SOL).unwrap();
    assert_err(&env.op_send_sol(p.buyback_authority), SijkaError::RecoveryRecipientInvalid);
    let a1 = env.lamports(&admin);
    assert_ok(&env.op_send_sol(admin));
    assert_eq!(env.lamports(&admin), a1 + SOL);
}

/// TR-24: the buyback escrow (`buyback_usdc`, the SOL budget on
/// `buyback_authority`) and the unpaid creator share (`creator_escrow_usdc`)
/// are never touched by op 1–6; tag 32 still pays the creator afterwards.
#[test]
fn tr24_no_op_touches_buyback_escrow_or_creator_share() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let (bb, ce) = (env.buyback_usdc, env.creator_escrow_usdc);
    env.ctx.mint_fake_usdc_to_token_account(bb, 11 * USDC);
    env.ctx.mint_fake_usdc_to_token_account(ce, 13 * USDC);
    let p = env.p;
    env.ctx.svm.airdrop(&p.buyback_authority, 2 * SOL).unwrap();
    env.ctx.svm.airdrop(&p.creator_escrow, SOL).unwrap();
    env.latch_via_maintenance(true);
    let before = env.protected_snapshot();
    println!("protected: {before:?}");
    let protected: Vec<Pubkey> = vec![bb, ce, p.buyback_authority, p.creator_escrow, p.swap_authority, p.bb_unwrap];

    env.ctx.svm.airdrop(&p.fee_inbox, SOL).unwrap();
    let vp = env.vault_phusd;
    env.donate_phusd(vp, 2 * USDC);
    let (er_usdc, er_phusd, admin) = (env.er_usdc, env.er_phusd, env.admin);
    let steps: Vec<(&str, Instruction)> = vec![
        ("op 5", env.op_send_token_ix(5, er_phusd)),
        ("op 6", env.op_withdraw_ix(6, 300 * USDC)),
        ("op 1", env.op_withdraw_ix(1, 0)),
        ("op 4", env.op_unwrap_ix()),
        ("op 2", env.op_send_token_ix(2, er_usdc)),
        ("op 3", env.op_send_sol_ix(admin)),
    ];
    for (name, ix) in steps {
        for m in &ix.accounts {
            assert!(!protected.contains(&m.pubkey), "{name} lists a protected account {}", m.pubkey);
        }
        env.tick(10);
        let r = env.send(STRANGER_SEED, vec![ix]);
        assert_ok(&r);
        assert_eq!(env.protected_snapshot(), before, "{name} touched a protected balance");
    }
    // SPEC v4: buyback_usdc is never a destination either.
    let vu = env.vault_usdc;
    env.ctx.mint_fake_usdc_to_token_account(vu, 5 * USDC);
    assert_err(&env.op_send_token(2, bb), SijkaError::RecoveryRecipientInvalid);
    assert_eq!(env.amount(&bb), 11 * USDC);
    assert_eq!(env.amount(&ce), 13 * USDC);
    // The accrued 20% is still paid by tag 32 in recovery mode.
    let r = env.pay_creator();
    println!("tag 32 in recovery mode: {}", err_text(&r));
    assert_ok(&r);
    assert_eq!(env.amount(&ce), 0);
    assert_eq!(env.amount(&ata(&env.creator, &env.fx.usdc)), 13 * USDC);
}

/// TR-22 (SPEC v4): there are no pauses at all; a non-zero byte at the former
/// `inflow_pause_mask@1152` is ignored by tag 50 / tag 51 (and by everything
/// else); the trading key keeps trading on Phoenix.
#[test]
fn tr22_pauses_do_not_stop_recovery() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let mark = env.mark("SOL");
    assert_ok(&env.ioc("SOL", 0, mark * 102 / 100, 10, false));
    env.edit_cfg(|m| m.bytes_mut()[1152] = 3);
    env.latch_via_maintenance(true);
    assert_ok(&env.cancel_all("SOL"));
    // Op 1 with the position (buffer kept), op 4, op 2.
    assert_ok(&env.op_withdraw(1, 0));
    assert_ok(&env.op_unwrap());
    let er = env.er_usdc;
    assert_ok(&env.op_send_token(2, er));
    let v = env.observe_after(60);
    assert_eq!(v.verdict, UP);
    // Tag 21 is RecoveryActive.
    let vu = env.vault_usdc;
    env.ctx.mint_fake_usdc_to_token_account(vu, 5 * USDC);
    assert_err(&env.deposit_ix_send(0), SijkaError::RecoveryActive);
}
