// Copyright (c) 2026 prt1sn. All rights reserved.
//! Trading and the other tags in recovery mode (SPEC §5.6.5, TR-14, TR-33,
//! TT-11, O-16). SPEC v3 (DECISIONS §19): tag 10 `trade` does not check the
//! recovery mode (T13); the trading key closes positions and cancels through
//! it, at any price. Deposits and harvest are refused; the admin can still
//! replace the key or turn trading off with tag 3.

use sijka_vault::error::SijkaError;

use crate::harness::*;
use crate::vault::*;

const USDC: u64 = 1_000_000;

/// TR-33 / TR-14 / TT-11: after the latch the trading key closes a long far
/// below the mark and cancels a resting bid through tag 10 (no vault balance
/// outside Phoenix moves); deposits and harvest are `RecoveryActive`, preview
/// reports 9; op 7 / op 8 do not exist; the admin turns trading off with tag
/// 3 and tag 10 then refuses the key.
#[test]
fn tr33_tr14_trading_key_in_recovery_mode() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let mark = env.mark("SOL");
    assert_ok(&env.ioc("SOL", 0, mark * 102 / 100, 10, false));
    assert_eq!(env.positions().iter().map(|p| p.1).collect::<Vec<_>>(), vec![10]);
    // A resting bid to cancel later.
    assert_ok(&env.post_only("SOL", 0, mark * 95 / 100, 3));

    env.latch_via_maintenance(true);
    let watched = [env.vault_usdc, env.vault_phusd, env.buyback_usdc, env.creator_escrow_usdc];
    let fee_inbox = env.p.fee_inbox;
    let snap = |env: &VaultEnv| {
        (watched.iter().map(|k| env.amount(k)).collect::<Vec<_>>(), env.lamports(&fee_inbox), env.collateral())
    };
    let s0 = snap(&env);

    // RO Ask 4 lots at 1 tick (any price): ok, position 6.
    assert_ok(&env.ioc("SOL", 1, 1, 4, true));
    assert_eq!(env.positions().iter().map(|p| p.1).collect::<Vec<_>>(), vec![6]);
    // The program does not restrict trading in recovery mode (T13): a
    // risk-increasing order of the key reaches Phoenix, which decides.
    let mark = env.mark("SOL");
    let r = env.ioc("SOL", 0, mark * 102 / 100, 1, false);
    println!("non-RO IOC of the trading key in recovery mode: {}", err_text(&r));
    // Close whatever is open, RO at any price.
    let open: i64 = env.positions().iter().map(|p| p.1).sum();
    if open > 0 {
        assert_ok(&env.ioc("SOL", 1, 1, open as u64, true));
    }
    assert!(env.positions().is_empty(), "positions {:?}", env.positions());
    // Cancel by the trading key.
    assert_ok(&env.cancel_all("SOL"));
    // A stranger cannot trade our account.
    let stranger = env.stranger;
    let r = env.ioc_as(STRANGER_SEED, stranger, "SOL", 1, 1, 1, true);
    assert_err(&r, SijkaError::UnauthorizedTrader);

    // Deposits and harvest are off; preview says Recovery; tag 50 still works.
    let vu = env.vault_usdc;
    env.ctx.mint_fake_usdc_to_token_account(vu, 3 * USDC);
    assert_err(&env.deposit_ix_send(0), SijkaError::RecoveryActive);
    let hv = env.harvest_ix();
    assert_err(&env.send(STRANGER_SEED, vec![hv]), SijkaError::RecoveryActive);
    let pv = env.preview_ix();
    let r = env.send(STRANGER_SEED, vec![pv]);
    let m = assert_ok(&r);
    let rd = &m.return_data.data;
    assert_eq!(&rd[..8], b"SJKRTHPV");
    assert_eq!(rd[9], 9, "harvest_preview status 9 Recovery");
    // Review accounting-2: status 9 is final, so the preview does not call
    // Hawkeye (whose stale-mark refusal would fail the whole simulation).
    let hk = format!("Program {} invoke", hawkeye_id());
    assert!(!m.logs.iter().any(|l| l.contains(&hk)), "Hawkeye called in recovery mode\n{}", m.logs.join("\n"));
    assert_err(&env.latch(), SijkaError::RecoveryAlreadyActive);
    let v = env.observe_after(60);
    assert_eq!(v.flags & 0x08, 0x08);

    // The old public op 7 / op 8 (O-16) do not exist.
    let mut ix = env.op_unwrap_ix();
    ix.data = vec![51, 7, 0, 0, 0, 0, 0, 0, 0, 1, 1];
    assert_err(&env.send(STRANGER_SEED, vec![ix.clone()]), SijkaError::InvalidInstructionData);
    ix.data = vec![51, 8, 1, 1];
    assert_err(&env.send(STRANGER_SEED, vec![ix]), SijkaError::InvalidInstructionData);

    // Trading moved no vault balance except the minted 3 USDC and PnL on C_hdr.
    let s1 = snap(&env);
    assert_eq!(s1.0[0], s0.0[0] + 3 * USDC, "vault_usdc: only the minted 3 USDC");
    assert_eq!(&s1.0[1..], &s0.0[1..], "vault_phusd, buyback_usdc, creator_escrow_usdc unchanged");
    assert_eq!(s1.1, s0.1, "fee_inbox unchanged");
    println!("C_hdr after the closes: {} → {}", s0.2, s1.2);

    // Tag 3 works in recovery mode: trading off; tag 10 then refuses the key.
    let phx = env.p.phx_authority;
    assert_ok(&env.set_trader(solana_pubkey::Pubkey::default()));
    assert_eq!(rd_key(&env.trader_data(), 120), phx, "position authority stays phx_authority");
    assert_eq!(env.cfg(|c| *c.trader()), [0u8; 32]);
    let r = env.ioc("SOL", 0, env.mark("SOL") * 102 / 100, 1, false);
    assert_err(&r, SijkaError::UnauthorizedTrader);
}
