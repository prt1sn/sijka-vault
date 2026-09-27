// Copyright (c) 2026 prt1sn. All rights reserved.
//! SBPFv3 build format (SIMD-0178/0189/0377) and SIMD-0500 on the built `.so`
//! (`SIJKA_VAULT_SO` or `target/deploy/sijka_vault.so`, built with
//! `cargo build-sbf --arch v3`).
//!
//! 1. The ELF is SBPFv3 and loads in the runtime's deployment environment for
//!    the mainnet feature set (strict ELF parser, `RequisiteVerifier`). Every
//!    `call` is resolved: syscalls (src 0) are ids registered in that
//!    environment, internal calls (src 1) land inside the bytecode and are not
//!    `call -1` (the unresolved-symbol pattern). The loader checks neither at
//!    deploy time; a miss would only fail when that path runs.
//! 2. With SIMD-0500 (`disable_sbpf_v0_v1_v2_deployment`) active, the real
//!    loader-v3 instructions deploy, upgrade and freeze (SetAuthority None) our
//!    binary, and the program runs after each step.
//! 3. Control: with SIMD-0500 active the loader refuses to freeze the same ELF
//!    marked SBPFv0 (`InvalidAccountData`); without the feature it allows it.
//!
//! LiteSVM runs the mainnet feature set (`LiteSVM::new()`), in which SBPFv3
//! is enabled (feature 5cC3fo…, slot 428 976 000) and SBPFv0 still executes,
//! so the Phoenix / pump mainnet binaries in the other tests stay as they are.
//!
//! Without the artifact the tests are skipped, unless `SIJKA_REQUIRE_SO=1` or
//! `RISE_SDK_LOCALNET_REQUIRE_PROGRAMS=1` (CI). Not built on Windows hosts.

#![cfg(not(windows))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::print_stderr,
    clippy::result_large_err
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use litesvm::LiteSVM;
use litesvm::types::TransactionResult;
use phoenix_rise_litesvm_test::sdk_localnet_vm_required;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program_runtime::execution_budget::SVMTransactionExecutionBudget;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_program_runtime::solana_sbpf::elf::Executable;
use solana_program_runtime::solana_sbpf::program::SBPFVersion;
use solana_program_runtime::solana_sbpf::verifier::RequisiteVerifier;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

/// `enable_sbpf_v3_deployment_and_execution` (SIMD-0178, SIMD-0189, SIMD-0377).
const SBPF_V3_FEATURE: Pubkey = Pubkey::from_str_const("5cC3foj77CWun58pC51ebHFUWavHWKarWyR5UUik7dnC");
/// Mainnet activation slot of the feature (getAccountInfo, 2026-09-26).
const SBPF_V3_MAINNET_SLOT: u64 = 428_976_000;
/// `disable_sbpf_v0_v1_v2_deployment` (SIMD-0500): not active on mainnet yet.
const SIMD_0500_FEATURE: Pubkey = Pubkey::from_str_const("B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g");

const LOADER_V3: Pubkey = Pubkey::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
const SYSTEM_PROGRAM: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");
const RENT_SYSVAR: Pubkey = Pubkey::from_str_const("SysvarRent111111111111111111111111111111111");
const CLOCK_SYSVAR: Pubkey = Pubkey::from_str_const("SysvarC1ock11111111111111111111111111111111");

/// `UpgradeableLoaderState` sizes: Buffer header 37, ProgramData header 45, Program 36.
const BUFFER_HEADER: usize = 37;
const PROGRAMDATA_HEADER: usize = 45;
const PROGRAM_LEN: usize = 36;
/// Bytes per loader `Write` (keeps the transaction under 1232 bytes).
const WRITE_CHUNK: usize = 900;
const E_FLAGS_OFFSET: usize = 48;

const UNKNOWN_INSTRUCTION: u32 = 0x534A_0001;
const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

// ------------------------------------------------------------- artifact ----

fn artifact_required() -> bool {
    let on = |k: &str| matches!(std::env::var(k).as_deref(), Ok("1") | Ok("true"));
    on("SIJKA_REQUIRE_SO") || sdk_localnet_vm_required()
}

fn program_so() -> Option<Vec<u8>> {
    let path = match std::env::var("SIJKA_VAULT_SO") {
        Ok(p) => Some(PathBuf::from(p)).filter(|p| p.exists()),
        Err(_) => {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            [manifest.join("../../target/deploy/sijka_vault.so"), manifest.join("target/deploy/sijka_vault.so")]
                .into_iter()
                .find(|p| p.exists())
        }
    };
    match path {
        Some(p) => Some(std::fs::read(p).unwrap()),
        None if artifact_required() => {
            panic!("sijka_vault.so not found; run cargo build-sbf --arch v3 or set SIJKA_VAULT_SO")
        }
        None => {
            eprintln!("skipping: sijka_vault.so not built");
            None
        }
    }
}

fn e_flags(elf: &[u8]) -> u32 {
    u32::from_le_bytes(elf[E_FLAGS_OFFSET..E_FLAGS_OFFSET + 4].try_into().unwrap())
}

// ------------------------------------------------------ 1. the bytecode ----

#[test]
fn mainnet_feature_set_runs_sbpf_v3_and_v0() {
    let fs = LiteSVM::mainnet_feature_set();
    assert_eq!(fs.activated_slot(&SBPF_V3_FEATURE), Some(SBPF_V3_MAINNET_SLOT));
    assert!(!fs.is_active(&SIMD_0500_FEATURE), "SIMD-0500 is not active on mainnet (2026-09-26)");
    let rf = fs.runtime_features();
    assert!(rf.enable_sbpf_v3_deployment_and_execution);
    // The Phoenix / pump / SPL mainnet binaries are SBPFv0: execution stays enabled.
    assert!(!rf.disable_sbpf_v0_execution || rf.reenable_sbpf_v0_execution);
}

#[test]
fn elf_is_sbpf_v3_and_every_call_resolves() {
    let Some(so) = program_so() else { return };
    assert_eq!(e_flags(&so), 3, "e_flags: build with cargo build-sbf --arch v3");
    assert_eq!(u16::from_le_bytes([so[18], so[19]]), 0xf7, "SBPFv3 requires e_machine EM_BPF");

    // Deployment environment for the mainnet feature set: reject_broken_elfs,
    // no `sol_alloc_free_`, strict ELF parser for v3.
    let features = LiteSVM::mainnet_feature_set().runtime_features();
    let budget = SVMTransactionExecutionBudget::new_with_defaults(features.raise_cpi_nesting_limit_to_8);
    let env = solana_syscalls::create_program_runtime_environment(&features, &budget, true, false)
        .expect("runtime environment");
    let exe = Executable::<InvokeContext<'static, 'static>>::load(&so, (*env).clone()).expect("the ELF loads");
    assert_eq!(exe.get_sbpf_version(), SBPFVersion::V3);
    exe.verify::<RequisiteVerifier>().expect("RequisiteVerifier");

    let registry = exe.get_loader().get_function_registry();
    let (_, text) = exe.get_text_bytes();
    let n = text.len() / 8;
    let mut syscalls: BTreeMap<String, usize> = BTreeMap::new();
    let (mut internal, mut callx) = (0usize, 0usize);
    let mut problems = Vec::new();
    let mut pc = 0usize;
    while pc < n {
        let i = &text[pc * 8..pc * 8 + 8];
        let (opc, dst, src) = (i[0], i[1] & 0x0f, i[1] >> 4);
        let imm = i32::from_le_bytes(i[4..8].try_into().unwrap());
        match opc {
            // lddw: 16 bytes.
            0x18 => pc += 1,
            0x85 if src == 0 => match registry.lookup_by_key(imm as u32) {
                Some((name, _)) => *syscalls.entry(String::from_utf8_lossy(name).into_owned()).or_default() += 1,
                None => problems.push(format!("pc {pc}: unknown syscall id {:#x}", imm as u32)),
            },
            0x85 if src == 1 => {
                let target = pc as i64 + 1 + i64::from(imm);
                if target == pc as i64 {
                    problems.push(format!("pc {pc}: call -1 (unresolved symbol)"));
                } else if target < 0 || target >= n as i64 {
                    problems.push(format!("pc {pc}: internal call outside the bytecode ({target})"));
                }
                internal += 1;
            }
            0x85 => problems.push(format!("pc {pc}: call with src {src}")),
            0x8d => {
                callx += 1;
                if dst > 9 || src != 0 || imm != 0 {
                    problems.push(format!("pc {pc}: callx not in the SBPFv3 encoding"));
                }
            }
            _ => {}
        }
        pc += 1;
    }
    eprintln!("sijka_vault.so: {} bytes, {n} instruction slots, {internal} internal calls, {callx} callx", so.len());
    eprintln!("syscalls: {syscalls:?}");
    assert!(problems.is_empty(), "unresolved calls:\n{}", problems.join("\n"));
    // The program must use CPI and logging through static syscalls.
    for name in
        ["sol_invoke_signed_c", "sol_log_", "sol_log_data", "sol_try_find_program_address", "sol_get_stack_height"]
    {
        assert!(syscalls.contains_key(name), "{name} not called: {syscalls:?}");
    }
}

// ----------------------------------------- 2. and 3. loader-v3 with SIMD-0500 ----

/// `LiteSVM::new()` with the mainnet feature set, optionally plus SIMD-0500.
fn svm(simd_0500: bool) -> LiteSVM {
    let mut fs = LiteSVM::mainnet_feature_set();
    if simd_0500 {
        fs.activate(&SIMD_0500_FEATURE, 0);
    }
    let mut svm = LiteSVM::default()
        .with_feature_set(fs)
        .with_builtins()
        .with_lamports(1_000_000 * LAMPORTS_PER_SOL)
        .with_sysvars()
        .with_feature_accounts()
        .with_default_programs()
        .with_sigverify(true)
        .with_blockhash_check(true)
        .with_transaction_history(0);
    svm.warp_to_slot(1_000);
    svm
}

fn send(svm: &mut LiteSVM, ixs: &[Instruction], payer: &Keypair, extra: &[&Keypair]) -> TransactionResult {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), &signers, svm.latest_blockhash());
    let r = svm.send_transaction(tx);
    svm.expire_blockhash();
    r
}

fn ok(r: TransactionResult, what: &str) {
    if let Err(e) = r {
        panic!("{what}: {:?}\n{}", e.err, e.meta.logs.join("\n"));
    }
}

fn create_account(from: &Pubkey, to: &Pubkey, lamports: u64, space: usize, owner: &Pubkey) -> Instruction {
    let mut data = vec![0u8; 4];
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&(space as u64).to_le_bytes());
    data.extend_from_slice(owner.as_ref());
    Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, true)],
        data,
    }
}

/// Loader-v3 instruction data: u32 LE variant ‖ bincode arguments.
fn loader_ix(variant: u32, args: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = variant.to_le_bytes().to_vec();
    data.extend_from_slice(args);
    Instruction { program_id: LOADER_V3, accounts, data }
}

/// Buffer with `elf`, authority = `auth` (InitializeBuffer + Write chunks).
fn write_buffer(svm: &mut LiteSVM, auth: &Keypair, elf: &[u8]) -> Pubkey {
    let buffer = Keypair::new();
    let space = BUFFER_HEADER + elf.len();
    let rent = svm.minimum_balance_for_rent_exemption(space);
    let init = loader_ix(
        0,
        &[],
        vec![AccountMeta::new(buffer.pubkey(), false), AccountMeta::new_readonly(auth.pubkey(), false)],
    );
    ok(
        send(svm, &[create_account(&auth.pubkey(), &buffer.pubkey(), rent, space, &LOADER_V3), init], auth, &[&buffer]),
        "create + InitializeBuffer",
    );
    for (k, chunk) in elf.chunks(WRITE_CHUNK).enumerate() {
        let mut args = ((k * WRITE_CHUNK) as u32).to_le_bytes().to_vec();
        args.extend_from_slice(&(chunk.len() as u64).to_le_bytes());
        args.extend_from_slice(chunk);
        let ix = loader_ix(
            1,
            &args,
            vec![AccountMeta::new(buffer.pubkey(), false), AccountMeta::new_readonly(auth.pubkey(), true)],
        );
        ok(send(svm, &[ix], auth, &[]), "Write");
    }
    buffer.pubkey()
}

fn programdata_of(program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[program.as_ref()], &LOADER_V3).0
}

fn set_authority_none(programdata: &Pubkey, auth: &Pubkey) -> Instruction {
    loader_ix(4, &[], vec![AccountMeta::new(*programdata, false), AccountMeta::new_readonly(*auth, true)])
}

/// The program runs: an unknown tag fails with our error code.
fn assert_runs(svm: &mut LiteSVM, program: &Pubkey, payer: &Keypair, when: &str) {
    let ix = Instruction { program_id: *program, accounts: vec![], data: vec![255] };
    let e = send(svm, &[ix], payer, &[]).expect_err("unknown tag must fail");
    let s = format!("{:?}", e.err);
    assert!(s.contains(&format!("Custom({UNKNOWN_INSTRUCTION})")), "{when}: {s}\n{}", e.meta.logs.join("\n"));
}

#[test]
fn simd_0500_deploy_upgrade_and_freeze_of_the_v3_build() {
    let Some(so) = program_so() else { return };
    let mut svm = svm(true);
    let auth = Keypair::new();
    svm.airdrop(&auth.pubkey(), 100 * LAMPORTS_PER_SOL).unwrap();

    // DeployWithMaxDataLen through a buffer (max_data_len = size, DECISIONS §16).
    let program = Keypair::new();
    let programdata = programdata_of(&program.pubkey());
    let buffer = write_buffer(&mut svm, &auth, &so);
    let rent = svm.minimum_balance_for_rent_exemption(PROGRAM_LEN);
    let deploy = loader_ix(
        2,
        &(so.len() as u64).to_le_bytes(),
        vec![
            AccountMeta::new(auth.pubkey(), true),
            AccountMeta::new(programdata, false),
            AccountMeta::new(program.pubkey(), false),
            AccountMeta::new(buffer, false),
            AccountMeta::new_readonly(RENT_SYSVAR, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(auth.pubkey(), true),
        ],
    );
    ok(
        send(
            &mut svm,
            &[create_account(&auth.pubkey(), &program.pubkey(), rent, PROGRAM_LEN, &LOADER_V3), deploy],
            &auth,
            &[&program],
        ),
        "DeployWithMaxDataLen under SIMD-0500",
    );
    svm.warp_to_slot(1_001);
    assert_runs(&mut svm, &program.pubkey(), &auth, "after deploy");

    // Upgrade (a pre-freeze fix) from a second buffer.
    let buffer2 = write_buffer(&mut svm, &auth, &so);
    let upgrade = loader_ix(
        3,
        &[],
        vec![
            AccountMeta::new(programdata, false),
            AccountMeta::new(program.pubkey(), false),
            AccountMeta::new(buffer2, false),
            AccountMeta::new(auth.pubkey(), false),
            AccountMeta::new_readonly(RENT_SYSVAR, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR, false),
            AccountMeta::new_readonly(auth.pubkey(), true),
        ],
    );
    ok(send(&mut svm, &[upgrade], &auth, &[]), "Upgrade under SIMD-0500");
    svm.warp_to_slot(1_002);
    assert_runs(&mut svm, &program.pubkey(), &auth, "after upgrade");

    // Freeze: SetAuthority without a new authority.
    ok(
        send(&mut svm, &[set_authority_none(&programdata, &auth.pubkey())], &auth, &[]),
        "SetAuthority(None) under SIMD-0500",
    );
    let pd = svm.get_account(&programdata).unwrap();
    assert_eq!(pd.data[12], 0, "ProgramData has no upgrade authority after the freeze");
    assert_eq!(e_flags(&pd.data[PROGRAMDATA_HEADER..]), 3);
    svm.warp_to_slot(1_003);
    assert_runs(&mut svm, &program.pubkey(), &auth, "after the freeze");
}

/// ProgramData with `elf` and upgrade authority `auth`, set directly.
fn put_programdata(svm: &mut LiteSVM, auth: &Pubkey, elf: &[u8]) -> Pubkey {
    let pd = Keypair::new().pubkey();
    let mut data = vec![0u8; PROGRAMDATA_HEADER];
    data[0] = 3;
    data[12] = 1;
    data[13..45].copy_from_slice(auth.as_ref());
    data.extend_from_slice(elf);
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());
    svm.set_account(pd, Account { lamports, data, owner: LOADER_V3, executable: false, rent_epoch: 0 }).unwrap();
    pd
}

#[test]
fn simd_0500_blocks_the_freeze_of_a_pre_v3_elf_only() {
    let Some(so) = program_so() else { return };
    let mut v0 = so.clone();
    v0[E_FLAGS_OFFSET..E_FLAGS_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
    // (SIMD-0500 active, ELF, freeze allowed)
    for (simd_0500, elf, allowed) in [(true, &so, true), (true, &v0, false), (false, &v0, true)] {
        let mut svm = svm(simd_0500);
        let auth = Keypair::new();
        svm.airdrop(&auth.pubkey(), 10 * LAMPORTS_PER_SOL).unwrap();
        let pd = put_programdata(&mut svm, &auth.pubkey(), elf);
        let r = send(&mut svm, &[set_authority_none(&pd, &auth.pubkey())], &auth, &[]);
        let case = format!("SIMD-0500 {simd_0500}, e_flags {}", e_flags(elf));
        if allowed {
            ok(r, &case);
            assert_eq!(svm.get_account(&pd).unwrap().data[12], 0, "{case}");
        } else {
            let e = r.expect_err(&case);
            assert!(format!("{:?}", e.err).contains("InvalidAccountData"), "{case}: {:?}", e.err);
            assert_eq!(svm.get_account(&pd).unwrap().data[12], 1, "{case}: authority unchanged");
        }
    }
}
