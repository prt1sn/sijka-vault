// Copyright (c) 2026 prt1sn. All rights reserved.
//! Runtime limits behind U-25 (account locks per transaction) with the
//! mainnet feature set LiteSVM ships (snapshot 2026-08-24; live mainnet
//! checked separately, see the final report).

use std::collections::BTreeSet;

use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::harness::*;
use crate::route::*;
use crate::swap::{SOL, fund_fee_inbox, honest};

/// `increase_tx_account_lock_limit` (Agave feature id).
pub fn lock_limit_feature() -> Pubkey {
    pk("9LZdXeKGeBV6hRLdxS1rHbHoEUsKqesCC2ZAPTPKJAbK")
}

fn transfer_with_extra_keys(payer: &Keypair, n_extra: usize) -> Instruction {
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&1u64.to_le_bytes());
    let mut accounts = vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new(payer.pubkey(), false)];
    for i in 0..n_extra {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        b[31] = 0x77;
        accounts.push(AccountMeta::new_readonly(Pubkey::new_from_array(b), false));
    }
    Instruction { program_id: system_program(), accounts, data }
}

#[test]
fn u25_account_lock_limit_is_64() {
    let mut svm = litesvm::LiteSVM::new();
    let payer = Keypair::new_from_array([0x25; 32]);
    svm.airdrop(&payer.pubkey(), 10 * SOL).unwrap();
    // The feature is not in the mainnet set LiteSVM ships.
    assert!(svm.get_account(&lock_limit_feature()).is_none(), "increase_tx_account_lock_limit is active in LiteSVM");
    // Unique keys: payer + System program + n.
    for (n, ok) in [(62usize, true), (63, false)] {
        let ix = transfer_with_extra_keys(&payer, n);
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], svm.latest_blockhash());
        let keys: BTreeSet<Pubkey> = tx.message.account_keys.iter().copied().collect();
        let r = svm.send_transaction(tx);
        svm.expire_blockhash();
        if ok {
            assert!(r.is_ok(), "{} unique keys must pass: {:?}", keys.len(), r.err());
            assert_eq!(keys.len(), 64);
        } else {
            let e = format!("{:?}", r.expect_err("65 keys must fail").err);
            assert!(e.contains("TooManyAccountLocks"), "{e}");
            assert_eq!(keys.len(), 65);
        }
    }
}

#[test]
fn u25_swap_transaction_budget() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    // Honest route padded with distinct read-only keys up to 64 / 65 unique
    // keys in the whole transaction (compute budget program included).
    for (target, ok) in [(64usize, true), (65, false)] {
        let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
        let mut ixs = vec![cu_limit(1_400_000), s.ix(&env)];
        let count = |ixs: &[Instruction], payer: &Pubkey| {
            let mut keys: BTreeSet<Pubkey> = BTreeSet::new();
            keys.insert(*payer);
            for ix in ixs {
                keys.insert(ix.program_id);
                keys.extend(ix.accounts.iter().map(|a| a.pubkey));
            }
            keys.len()
        };
        let payer = env.keeper.pubkey();
        let mut i = 0u64;
        while count(&ixs, &payer) < target {
            i += 1;
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&i.to_le_bytes());
            b[31] = 0x78;
            s.route.push(AccountMeta::new_readonly(Pubkey::new_from_array(b), false));
            ixs = vec![cu_limit(1_400_000), s.ix(&env)];
        }
        assert!(s.route.len() <= 64);
        let r = env.send(ixs, &[]);
        if ok {
            expect_ok(r);
        } else {
            expect_runtime_err(r, "TooManyAccountLocks");
        }
        eprintln!("u25: {target} unique keys, route tail {}", s.route.len());
    }
}
