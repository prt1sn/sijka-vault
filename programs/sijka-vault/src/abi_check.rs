// Copyright (c) 2026 prt1sn. All rights reserved.
//! Consistency check between the Rust program, `abi/sijka-vault.json` (built
//! from docs/SPEC.md by `abi/gen-from-spec.mjs`) and therefore the TS SDK,
//! which re-exports the same file.
//!
//! Checked: every instruction shape (tag, op, name, fixed accounts, data
//! length, tails) and the dispatcher's rejection of wrong account counts and
//! data lengths; every error code, name and class; every field of the state
//! layouts; event tags and lengths; pinned buyback slots; PDA seeds; program
//! addresses; the tag 10 allowlist.

use std::collections::BTreeMap;
use std::str::FromStr;

use serde_json::Value;

use crate::constants as c;
use crate::error::SijkaError;
use crate::instructions::{AccTail, DataTail, SHAPES, Shape};
use crate::state::FieldSpec;
use crate::util::test_utils::{dummy_accounts, infos};

const ABI_JSON: &str = include_str!("../../../abi/sijka-vault.json");

fn abi() -> Value {
    serde_json::from_str(ABI_JSON).expect("abi/sijka-vault.json parses")
}

fn u(v: &Value) -> usize {
    v.as_u64().expect("unsigned number") as usize
}

fn field_offset(ix: &Value, name: &str) -> usize {
    let f = ix["data"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == name)
        .unwrap_or_else(|| panic!("{}: no data field {name}", ix["name"]));
    u(&f["offset"])
}

fn find_shape(tag: u8, op: Option<u8>) -> &'static Shape {
    SHAPES
        .iter()
        .find(|s| s.tag == tag && s.op == op)
        .unwrap_or_else(|| panic!("no Rust shape for tag {tag} op {op:?}"))
}

#[test]
fn instruction_shapes_match_abi() {
    let a = abi();
    let ixs = a["instructions"].as_array().unwrap();
    assert_eq!(ixs.len(), SHAPES.len(), "instruction count");
    for ix in ixs {
        let tag = u(&ix["tag"]) as u8;
        let op = ix["op"].as_u64().map(|o| o as u8);
        let s = find_shape(tag, op);
        let name = ix["name"].as_str().unwrap();
        assert_eq!(s.name, name, "tag {tag} op {op:?}");
        assert_eq!(s.accounts, ix["accounts"].as_array().unwrap().len(), "{name}: fixed accounts");
        assert_eq!(s.data, u(&ix["data"]["size"]), "{name}: fixed data");
        // Tag and op bytes.
        assert_eq!(field_offset(ix, "tag"), 0);
        if op.is_some() {
            assert_eq!(field_offset(ix, "op"), u(&ix["opOffset"]), "{name}: op offset");
        }
        // Account tail.
        let tail = &ix["tail"];
        match s.acc_tail {
            AccTail::None => assert!(tail.is_null(), "{name}: unexpected tail"),
            AccTail::Arenas { gti_off } => {
                assert_eq!(tail["kind"], "arenas", "{name}");
                assert_eq!(gti_off, u(&tail["gtiCountOffset"]), "{name}: gti offset");
                assert_eq!(gti_off + 1, u(&tail["atbCountOffset"]), "{name}: atb offset");
                assert_eq!(u(&tail["max"]), c::MAX_GTI);
                assert_eq!(u(&tail["max"]), c::MAX_ATB);
            }
            AccTail::Route => {
                assert_eq!(tail["kind"], "route", "{name}");
                assert_eq!(u(&tail["max"]), c::MAX_ROUTE_ACCOUNTS);
            }
            AccTail::PhoenixIx => {
                assert_eq!(tail["kind"], "phoenix", "{name}");
                assert_eq!(u(&tail["max"]), c::MAX_TRADE_ACCOUNTS);
                let min = c::TRADE_ALLOWLIST.iter().map(|r| r.min_accounts).min().unwrap();
                assert_eq!(u(&tail["min"]), min);
            }
        }
        // Data tail.
        let var = &ix["variable"];
        match s.data_tail {
            DataTail::None => assert!(var.is_null(), "{name}: unexpected variable data"),
            DataTail::Bytes { len_off, min, max } => {
                assert_eq!(var["kind"], "jupiter_data", "{name}");
                assert_eq!(len_off, field_offset(ix, var["lengthField"].as_str().unwrap()), "{name}: len offset");
                assert_eq!(min, u(&var["min"]));
                assert_eq!(max, u(&var["max"]));
            }
            DataTail::PhoenixIx => {
                assert_eq!(var["kind"], "phoenix_data", "{name}");
                assert_eq!(u(&var["min"]), 0);
                assert!(var["max"].is_null(), "{name}: the program sets no upper bound");
            }
        }
    }
}

/// Instruction data of the exact shape, with tails of minimal valid size.
fn minimal_data(s: &Shape) -> Vec<u8> {
    let mut d = vec![0u8; s.data];
    d[0] = s.tag;
    if let Some(op) = s.op {
        d[1] = op;
    }
    if let AccTail::Arenas { gti_off } = s.acc_tail {
        d[gti_off] = 1;
        d[gti_off + 1] = 1;
    }
    match s.data_tail {
        DataTail::None | DataTail::PhoenixIx => {}
        DataTail::Bytes { len_off, min, .. } => {
            d[len_off..len_off + 2].copy_from_slice(&(min as u16).to_le_bytes());
            d.extend(std::iter::repeat_n(0u8, min));
        }
    }
    d
}

fn expected_accounts(s: &Shape) -> usize {
    match s.acc_tail {
        AccTail::None => s.accounts,
        // g = a = 1 (see `minimal_data`).
        AccTail::Arenas { .. } => s.accounts + 2,
        // One route account.
        AccTail::Route => s.accounts + 1,
        // Tag 10: the fixed accounts are the whole shape check.
        AccTail::PhoenixIx => s.accounts,
    }
}

#[test]
fn dispatcher_rejects_wrong_counts_and_lengths() {
    let program = [0x11u8; 32];
    let pool = dummy_accounts(120);
    let all = infos(&pool);
    for s in SHAPES {
        let data = minimal_data(s);
        let n = expected_accounts(s);
        let run = |accounts: usize, data: &[u8]| crate::process_instruction(&program, &all[..accounts], data);

        // One account too many / too few.
        let too_many = run(n + 1, &data);
        let too_few = run(n - 1, &data);
        match s.acc_tail {
            AccTail::Route => {
                assert_eq!(too_few, Err(SijkaError::JupiterTooManyAccounts.into()), "{}: route n = 0", s.name);
                assert_eq!(run(s.accounts - 1, &data), Err(SijkaError::InvalidAccountCount.into()), "{}", s.name);
                assert_eq!(
                    run(s.accounts + c::MAX_ROUTE_ACCOUNTS + 1, &data),
                    Err(SijkaError::JupiterTooManyAccounts.into()),
                    "{}: route n = 65",
                    s.name
                );
                assert_ne!(too_many, Err(SijkaError::InvalidAccountCount.into()), "{}", s.name);
            }
            AccTail::PhoenixIx => {
                // Tag 10: any number of Phoenix accounts passes the shape
                // check (T4 decides later); fewer than 3 fixed ones do not.
                assert_eq!(too_few, Err(SijkaError::InvalidAccountCount.into()), "{}: -1 account", s.name);
                assert_ne!(too_many, Err(SijkaError::InvalidAccountCount.into()), "{}", s.name);
                for len in [1usize, 8, 9, 100] {
                    let mut d = vec![0u8; len];
                    d[0] = s.tag;
                    let r = run(n + 5, &d);
                    assert_ne!(r, Err(SijkaError::InvalidInstructionData.into()), "{}: {len} bytes", s.name);
                    assert_ne!(r, Err(SijkaError::InvalidAccountCount.into()), "{}: {len} bytes", s.name);
                }
                continue;
            }
            _ => {
                assert_eq!(too_many, Err(SijkaError::InvalidAccountCount.into()), "{}: +1 account", s.name);
                assert_eq!(too_few, Err(SijkaError::InvalidAccountCount.into()), "{}: -1 account", s.name);
            }
        }

        // One byte too many / too few.
        let mut long = data.clone();
        long.push(0);
        assert_eq!(run(n, &long), Err(SijkaError::InvalidInstructionData.into()), "{}: +1 byte", s.name);
        let short = &data[..data.len() - 1];
        assert_eq!(run(n, short), Err(SijkaError::InvalidInstructionData.into()), "{}: -1 byte", s.name);

        // The exact shape passes the shape check.
        let exact = run(n, &data);
        assert_ne!(exact, Err(SijkaError::InvalidAccountCount.into()), "{}: exact shape", s.name);
        assert_ne!(exact, Err(SijkaError::InvalidInstructionData.into()), "{}: exact shape", s.name);
    }
}

#[test]
fn error_codes_match_abi() {
    let a = abi();
    let errs = a["errors"].as_array().unwrap();
    assert_eq!(u(&a["errorBase"]) as u32, crate::error::ERROR_BASE);
    let rust: BTreeMap<&str, SijkaError> = SijkaError::ALL.iter().map(|e| (e.name(), *e)).collect();
    assert_eq!(errs.len(), rust.len(), "error count");
    for e in errs {
        let name = e["name"].as_str().unwrap();
        let r = rust.get(name).unwrap_or_else(|| panic!("error {name} missing in Rust"));
        assert_eq!(u64::from(r.code()), e["code"].as_u64().unwrap(), "{name}: code");
        assert_eq!(r.class(), e["class"].as_str().unwrap(), "{name}: class");
    }
}

fn assert_layout(a: &Value, key: &str, fields: &[FieldSpec], len: usize) {
    let l = &a["accounts"][key];
    assert_eq!(u(&l["size"]), len, "{key}: size");
    let jf = l["fields"].as_array().unwrap();
    assert_eq!(jf.len(), fields.len(), "{key}: field count");
    for (j, r) in jf.iter().zip(fields) {
        assert_eq!(j["name"].as_str().unwrap(), r.name, "{key}: field name at {}", r.offset);
        assert_eq!(u(&j["offset"]), r.offset, "{key}.{}: offset", r.name);
        assert_eq!(u(&j["size"]), r.size, "{key}.{}: size", r.name);
    }
}

#[test]
fn state_layouts_match_abi() {
    use crate::state::{buyback_state as bs, config as cf};
    let a = abi();
    assert_layout(&a, "Config", cf::FIELDS, cf::CONFIG_LEN);
    assert_layout(&a, "HarvestParams", cf::harvest_params::FIELDS, cf::harvest_params::HARVEST_PARAMS_LEN);
    assert_layout(&a, "InflowParams", cf::inflow_params::FIELDS, cf::inflow_params::INFLOW_PARAMS_LEN);
    assert_layout(&a, "BuybackState", bs::FIELDS, bs::BUYBACK_STATE_LEN);
    assert_layout(&a, "BuybackParams", bs::buyback_params::FIELDS, bs::buyback_params::BUYBACK_PARAMS_LEN);
    // Discriminators and versions.
    assert_eq!(a["accounts"]["Config"]["discriminator"].as_str().unwrap().as_bytes(), &c::DISC_CONFIG);
    assert_eq!(a["accounts"]["BuybackState"]["discriminator"].as_str().unwrap().as_bytes(), &c::DISC_BUYBACK_STATE);
    // Retired with SPEC v2: no TradeConfig account or its parameter structs.
    for k in ["TradeConfig", "TradeParams", "MarketEntry", "MarketParams"] {
        assert!(a["accounts"][k].is_null(), "{k} must not be in the ABI");
    }
    for k in ["Config", "BuybackState"] {
        assert_eq!(u(&a["accounts"][k]["version"]), usize::from(c::ACCOUNT_VERSION));
    }
    // Pinned pump addresses k0..k26.
    let pinned = a["buybackPinned"].as_array().unwrap();
    assert_eq!(pinned.len(), bs::PINNED_COUNT);
    for (k, p) in pinned.iter().enumerate() {
        assert_eq!(p["name"].as_str().unwrap(), bs::pinned::NAMES[k], "k{k}");
        assert_eq!(Some(u(&p["offset"])), bs::pinned_offset(k), "k{k} offset");
    }
}

#[test]
fn events_match_abi() {
    let a = abi();
    let evs = a["events"].as_array().unwrap();
    assert_eq!(evs.len(), crate::events::EVENTS.len());
    for (j, (tag, len)) in evs.iter().zip(crate::events::EVENTS) {
        assert_eq!(j["tag"].as_str().unwrap().as_bytes(), *tag);
        assert_eq!(u(&j["size"]), *len, "{}", j["tag"]);
    }
}

/// SPEC §5.2.1 / §8.2.2: `abi.json.trade_allowlist` is `TRADE_ALLOWLIST`.
#[test]
fn trade_allowlist_matches_abi() {
    use phoenix_rise::ix::discriminants::PhoenixInstruction;
    let a = abi();
    assert_eq!(u(&a["max_trade_accounts"]), c::MAX_TRADE_ACCOUNTS);
    let list = a["trade_allowlist"].as_array().unwrap();
    assert_eq!(list.len(), c::TRADE_ALLOWLIST.len());
    for (j, r) in list.iter().zip(c::TRADE_ALLOWLIST.iter()) {
        let name = j["name"].as_str().unwrap();
        let ix = PhoenixInstruction::from_tag(r.disc).unwrap();
        assert_eq!(ix.instruction_name(), name);
        let hex: String = r.disc.to_le_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(j["disc"].as_str().unwrap(), hex, "{name}");
        assert_eq!(u(&j["tr"]), r.trader, "{name}: TR");
        let au = match r.wallet {
            c::TraderWalletSlot::At(i) => i.to_string(),
            c::TraderWalletSlot::NMinus3 => "n-3".to_string(),
        };
        assert_eq!(j["au"].as_str().unwrap(), au, "{name}: AU");
        assert_eq!(u(&j["min"]), r.min_accounts, "{name}: MIN");
    }
}

#[test]
fn pda_seeds_match_abi() {
    let a = abi();
    let want: BTreeMap<&str, &[u8]> = [
        ("config", c::SEED_CONFIG),
        ("buyback_state", c::SEED_BUYBACK_STATE),
        ("fee_inbox", c::SEED_FEE_INBOX),
        ("phx_authority", c::SEED_PHX_AUTHORITY),
        ("swap_authority", c::SEED_SWAP_AUTHORITY),
        ("buyback_authority", c::SEED_BUYBACK_AUTHORITY),
        ("rent_payer", c::SEED_RENT_PAYER),
        ("creator_escrow", c::SEED_CREATOR_ESCROW),
        ("bb_unwrap", c::SEED_BB_UNWRAP),
    ]
    .into_iter()
    .collect();
    let pdas = a["pdas"].as_array().unwrap();
    assert_eq!(pdas.len(), want.len());
    for p in pdas {
        let name = p["name"].as_str().unwrap();
        let seeds = p["seeds"].as_array().unwrap();
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].as_str().unwrap().as_bytes(), want[name], "{name}");
    }
}

#[test]
fn program_addresses_match_abi() {
    let a = abi();
    let rust: BTreeMap<&str, &[u8; 32]> = [
        ("PHOENIX_PROGRAM_ID", &c::PHOENIX_PROGRAM_ID),
        ("PHOENIX_LOG_AUTHORITY", &c::PHOENIX_LOG_AUTHORITY),
        ("PHOENIX_GLOBAL_CONFIG", &c::PHOENIX_GLOBAL_CONFIG),
        ("HAWKEYE_PROGRAM_ID", &c::HAWKEYE_PROGRAM_ID),
        ("EMBER_PROGRAM_ID", &c::EMBER_PROGRAM_ID),
        ("EMBER_STATE", &c::EMBER_STATE),
        ("EMBER_VAULT", &c::EMBER_VAULT),
        ("JUPITER_V6", &c::JUPITER_V6),
        ("PUMP_PROGRAM", &c::PUMP_PROGRAM),
        ("PUMP_AMM_PROGRAM", &c::PUMP_AMM_PROGRAM),
        ("PUMP_FEES_PROGRAM", &c::PUMP_FEES_PROGRAM),
        ("PUMP_GLOBAL", &c::PUMP_GLOBAL),
        ("PUMP_EVENT_AUTHORITY", &c::PUMP_EVENT_AUTHORITY),
        ("PUMP_GVA", &c::PUMP_GVA),
        ("PUMP_FEE_CONFIG", &c::PUMP_FEE_CONFIG),
        ("AMM_GLOBAL_CONFIG", &c::AMM_GLOBAL_CONFIG),
        ("AMM_EVENT_AUTHORITY", &c::AMM_EVENT_AUTHORITY),
        ("AMM_GVA", &c::AMM_GVA),
        ("AMM_FEE_CONFIG", &c::AMM_FEE_CONFIG),
        ("SPL_TOKEN_PROGRAM_ID", &c::SPL_TOKEN_PROGRAM_ID),
        ("TOKEN_2022_PROGRAM_ID", &c::TOKEN_2022_PROGRAM_ID),
        ("ATA_PROGRAM_ID", &c::ATA_PROGRAM_ID),
        ("SYSTEM_PROGRAM_ID", &c::SYSTEM_PROGRAM_ID),
        ("COMPUTE_BUDGET_PROGRAM_ID", &c::COMPUTE_BUDGET_PROGRAM_ID),
        ("INSTRUCTIONS_SYSVAR", &c::INSTRUCTIONS_SYSVAR),
        ("BPF_LOADER_UPGRADEABLE_ID", &c::BPF_LOADER_UPGRADEABLE_ID),
        ("PHOENIX_PROGRAM_DATA", &c::PHOENIX_PROGRAM_DATA),
        ("JITO_DONT_FRONT", &c::JITO_DONT_FRONT),
    ]
    .into_iter()
    .collect();
    let consts = a["constants"].as_object().unwrap();
    assert_eq!(consts.len(), rust.len(), "address constant count");
    for (name, v) in consts {
        let want = rust.get(name.as_str()).unwrap_or_else(|| panic!("{name} missing in Rust"));
        let got = solana_pubkey::Pubkey::from_str(v.as_str().unwrap()).unwrap().to_bytes();
        assert_eq!(&got, *want, "{name}");
    }
}
