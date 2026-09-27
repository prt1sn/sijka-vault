// Copyright (c) 2026 prt1sn. All rights reserved.
//! LiteSVM smoke tests: the built `.so` loads and the dispatcher rejects
//! malformed input with our error codes. Runs in CI on Linux after
//! `cargo build-sbf` (`SIJKA_VAULT_SO` or `target/deploy/sijka_vault.so`).
//!
//! Without the artifact the tests are skipped, unless
//! `RISE_SDK_LOCALNET_REQUIRE_PROGRAMS=1` (or `SIJKA_REQUIRE_SO=1`) is set, in
//! which case a missing artifact fails the run. The second test also loads the
//! Phoenix / Ember / Hawkeye binaries through `phoenix-rise-litesvm-test`
//! (`RISE_SDK_LOCALNET_*_SO`; `PHOENIX_MAINNET_BPF_PROGRAMS=1` fetches them
//! outside CI).
//!
//! Not built on Windows hosts (litesvm needs a MinGW `dlltool` there).

#![cfg(not(windows))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::print_stderr)]

use std::path::PathBuf;

use litesvm::LiteSVM;
use phoenix_rise_litesvm_test::{
    SdkLocalnetContext, SdkLocalnetProgram, default_sdk_localnet_fixture, find_sdk_localnet_program_paths,
    sdk_localnet_vm_required,
};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const UNKNOWN_INSTRUCTION: u32 = 0x534A_0001;
const INVALID_INSTRUCTION_DATA: u32 = 0x534A_0002;
const INVALID_ACCOUNT_COUNT: u32 = 0x534A_0003;

fn artifact_required() -> bool {
    let on = |k: &str| matches!(std::env::var(k).as_deref(), Ok("1") | Ok("true"));
    on("SIJKA_REQUIRE_SO") || sdk_localnet_vm_required()
}

fn program_so() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SIJKA_VAULT_SO") {
        return Some(PathBuf::from(p)).filter(|p| p.exists());
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    [manifest.join("../../target/deploy/sijka_vault.so"), manifest.join("target/deploy/sijka_vault.so")]
        .into_iter()
        .find(|p| p.exists())
}

fn require_so() -> Option<PathBuf> {
    match program_so() {
        Some(p) => Some(p),
        None if artifact_required() => panic!("sijka_vault.so not found; run cargo build-sbf or set SIJKA_VAULT_SO"),
        None => {
            eprintln!("skipping: sijka_vault.so not built");
            None
        }
    }
}

fn custom_code(err: &impl std::fmt::Debug) -> String {
    format!("{err:?}")
}

#[test]
fn program_loads_and_rejects_malformed_input() {
    let Some(so) = require_so() else { return };
    let bytes = std::fs::read(&so).unwrap();
    let mut svm = LiteSVM::new();
    let program_id = Keypair::new().pubkey();
    svm.add_program(program_id, &bytes).unwrap();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let dummy: Pubkey = Keypair::new().pubkey();
    let cases: Vec<(Vec<u8>, Vec<AccountMeta>, u32)> = vec![
        (vec![255], vec![], UNKNOWN_INSTRUCTION),
        (vec![9], vec![], UNKNOWN_INSTRUCTION),
        (vec![52], vec![], UNKNOWN_INSTRUCTION),
        (vec![], vec![], INVALID_INSTRUCTION_DATA),
        (vec![0], vec![], INVALID_INSTRUCTION_DATA),
        (vec![51, 9], vec![], INVALID_INSTRUCTION_DATA),
        // Tag 51 has no trading ops (O-16): the former op 7 / op 8 data is rejected.
        (vec![51, 7, 0, 0, 0, 0, 0, 0, 0, 1, 1], vec![], INVALID_INSTRUCTION_DATA),
        (vec![51, 8, 1, 1], vec![], INVALID_INSTRUCTION_DATA),
        (vec![3; 33], vec![], INVALID_ACCOUNT_COUNT),
        // Tag 10 `trade` needs its three fixed accounts first (SPEC v3).
        (vec![10], vec![], INVALID_ACCOUNT_COUNT),
        (vec![10; 40], vec![AccountMeta::new_readonly(dummy, false)], INVALID_ACCOUNT_COUNT),
        (vec![50], vec![AccountMeta::new_readonly(dummy, false)], INVALID_ACCOUNT_COUNT),
    ];
    for (data, accounts, code) in cases {
        let ix = Instruction { program_id, accounts, data: data.clone() };
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], svm.latest_blockhash());
        let err = svm.send_transaction(tx).expect_err("malformed instruction must fail");
        let s = custom_code(&err.err);
        assert!(s.contains(&format!("Custom({code})")), "data {data:?}: got {s}");
        assert!(err.meta.logs.iter().any(|l| l.contains("Sijka: ")), "error log line missing: {:?}", err.meta.logs);
        svm.expire_blockhash();
    }
}

#[test]
fn program_loads_next_to_phoenix_fixture() {
    let Some(paths) = find_sdk_localnet_program_paths() else {
        if sdk_localnet_vm_required() {
            panic!("missing Phoenix/Ember/Hawkeye SBF artifacts (RISE_SDK_LOCALNET_*_SO)");
        }
        eprintln!("skipping: Phoenix protocol artifacts missing");
        return;
    };
    let Some(so) = require_so() else { return };
    let fixture = default_sdk_localnet_fixture().expect("fixture parses");
    let program_id = Keypair::new().pubkey();
    let mut ctx = SdkLocalnetContext::new_with_programs(fixture, paths, [SdkLocalnetProgram::new(program_id, so)]);
    ctx.execute_setup();
    let ix = Instruction { program_id, accounts: vec![], data: vec![255] };
    let err = ctx.try_send_instructions_with_metadata(vec![ix], "payer").expect_err("unknown tag must fail");
    let s = custom_code(&err.err);
    assert!(s.contains(&format!("Custom({UNKNOWN_INSTRUCTION})")), "got {s}");
}
