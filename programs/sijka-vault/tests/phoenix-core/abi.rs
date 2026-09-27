// Copyright (c) 2026 prt1sn. All rights reserved.
//! Layouts, error codes and event shapes from `abi/sijka-vault.json` (the
//! manifest generated from docs/SPEC.md). The tests read and write program
//! state only through these names, so a layout drift between the program and
//! the SPEC shows up as a failing assertion instead of a silently matching one.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::Value;

const ABI_JSON: &str = include_str!("../../../../abi/sijka-vault.json");

#[derive(Clone, Debug)]
pub struct Field {
    pub offset: usize,
    pub size: usize,
    pub ty: String,
}

#[derive(Clone, Debug, Default)]
pub struct Layout {
    pub size: usize,
    pub fields: HashMap<String, Field>,
}

impl Layout {
    pub fn field(&self, name: &str) -> &Field {
        self.fields.get(name).unwrap_or_else(|| panic!("ABI: no field {name}"))
    }

    pub fn u8(&self, data: &[u8], name: &str) -> u8 {
        let f = self.field(name);
        assert_eq!(f.size, 1, "{name} is not 1 byte");
        data[f.offset]
    }

    pub fn u16(&self, data: &[u8], name: &str) -> u16 {
        let f = self.field(name);
        assert_eq!(f.size, 2, "{name} is not 2 bytes");
        u16::from_le_bytes(data[f.offset..f.offset + 2].try_into().unwrap())
    }

    pub fn u32(&self, data: &[u8], name: &str) -> u32 {
        let f = self.field(name);
        assert_eq!(f.size, 4, "{name} is not 4 bytes");
        u32::from_le_bytes(data[f.offset..f.offset + 4].try_into().unwrap())
    }

    pub fn u64(&self, data: &[u8], name: &str) -> u64 {
        let f = self.field(name);
        assert_eq!(f.size, 8, "{name} is not 8 bytes");
        u64::from_le_bytes(data[f.offset..f.offset + 8].try_into().unwrap())
    }

    pub fn i64(&self, data: &[u8], name: &str) -> i64 {
        self.u64(data, name) as i64
    }

    pub fn key(&self, data: &[u8], name: &str) -> [u8; 32] {
        let f = self.field(name);
        assert_eq!(f.size, 32, "{name} is not 32 bytes");
        data[f.offset..f.offset + 32].try_into().unwrap()
    }

    pub fn bytes<'a>(&self, data: &'a [u8], name: &str) -> &'a [u8] {
        let f = self.field(name);
        &data[f.offset..f.offset + f.size]
    }

    /// Write an integer field (little-endian, `size` bytes).
    pub fn put(&self, data: &mut [u8], name: &str, value: u128) {
        let f = self.field(name);
        assert!(f.size <= 16, "{name} is not an integer field");
        let b = value.to_le_bytes();
        data[f.offset..f.offset + f.size].copy_from_slice(&b[..f.size]);
    }

    pub fn put_bytes(&self, data: &mut [u8], name: &str, value: &[u8]) {
        let f = self.field(name);
        assert_eq!(f.size, value.len(), "{name} size");
        data[f.offset..f.offset + f.size].copy_from_slice(value);
    }

    /// Encode a whole struct from `(field, value)` pairs; every other byte is 0.
    pub fn encode(&self, values: &[(&str, u128)]) -> Vec<u8> {
        let mut out = vec![0u8; self.size];
        for (name, v) in values {
            self.put(&mut out, name, *v);
        }
        out
    }
}

pub struct Abi {
    pub layouts: HashMap<String, Layout>,
    pub events: HashMap<String, Layout>,
    pub errors: HashMap<String, u32>,
    pub instructions: Vec<Value>,
    pub root: Value,
}

fn parse_layout(v: &Value) -> Layout {
    let mut fields = HashMap::new();
    for f in v["fields"].as_array().expect("fields") {
        fields.insert(
            f["name"].as_str().unwrap().to_string(),
            Field {
                offset: f["offset"].as_u64().unwrap() as usize,
                size: f["size"].as_u64().unwrap() as usize,
                ty: f["type"].as_str().unwrap().to_string(),
            },
        );
    }
    Layout { size: v["size"].as_u64().unwrap() as usize, fields }
}

pub fn abi() -> &'static Abi {
    static ABI: OnceLock<Abi> = OnceLock::new();
    ABI.get_or_init(|| {
        let root: Value = serde_json::from_str(ABI_JSON).expect("abi json");
        let mut layouts = HashMap::new();
        for (k, v) in root["accounts"].as_object().expect("accounts") {
            layouts.insert(k.clone(), parse_layout(v));
        }
        let mut events = HashMap::new();
        for e in root["events"].as_array().expect("events") {
            events.insert(e["tag"].as_str().unwrap().to_string(), parse_layout(e));
        }
        let mut errors = HashMap::new();
        for e in root["errors"].as_array().expect("errors") {
            errors.insert(e["name"].as_str().unwrap().to_string(), e["code"].as_u64().unwrap() as u32);
        }
        let instructions = root["instructions"].as_array().expect("instructions").clone();
        Abi { layouts, events, errors, instructions, root }
    })
}

pub fn layout(name: &str) -> &'static Layout {
    abi().layouts.get(name).unwrap_or_else(|| panic!("ABI: no layout {name}"))
}

pub fn event(tag: &str) -> &'static Layout {
    abi().events.get(tag).unwrap_or_else(|| panic!("ABI: no event {tag}"))
}

pub fn err(name: &str) -> u32 {
    *abi().errors.get(name).unwrap_or_else(|| panic!("ABI: no error {name}"))
}

pub fn constant(name: &str) -> String {
    abi().root["constants"][name].as_str().unwrap_or_else(|| panic!("ABI: no constant {name}")).to_string()
}

/// `(fixed account count, [writable], [signer])` of an instruction (by name).
pub fn ix_accounts(name: &str) -> Vec<(String, bool, bool)> {
    let ix = abi()
        .instructions
        .iter()
        .find(|i| i["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("ABI: no instruction {name}"));
    ix["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (a["name"].as_str().unwrap().to_string(), a["writable"].as_bool().unwrap(), a["signer"].as_bool().unwrap())
        })
        .collect()
}

pub fn ix_data_size(name: &str) -> usize {
    let ix = abi().instructions.iter().find(|i| i["name"].as_str() == Some(name)).unwrap();
    ix["data"]["size"].as_u64().unwrap() as usize
}

/// One entry of the tag 10 allowlist (`trade_allowlist`, SPEC §5.2.1).
#[derive(Clone, Debug)]
pub struct AllowedTrade {
    pub name: String,
    /// `data[1..9]` of tag 10 (the Phoenix discriminator bytes).
    pub disc: [u8; 8],
    /// Index of the trader account in `P`.
    pub tr: usize,
    /// Index of the Phoenix signer slot: a number or `"n-3"`.
    pub au: String,
    /// Minimum `n` at `g = a = 1`.
    pub min: usize,
}

pub fn trade_allowlist() -> Vec<AllowedTrade> {
    abi().root["trade_allowlist"]
        .as_array()
        .expect("ABI: trade_allowlist")
        .iter()
        .map(|e| {
            let h = e["disc"].as_str().unwrap();
            let mut disc = [0u8; 8];
            for (i, b) in disc.iter_mut().enumerate() {
                *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
            }
            AllowedTrade {
                name: e["name"].as_str().unwrap().to_string(),
                disc,
                tr: e["tr"].as_u64().unwrap() as usize,
                au: e["au"].as_str().unwrap().to_string(),
                min: e["min"].as_u64().unwrap() as usize,
            }
        })
        .collect()
}

/// `MAX_TRADE_ACCOUNTS` (T4).
pub fn max_trade_accounts() -> usize {
    abi().root["max_trade_accounts"].as_u64().expect("ABI: max_trade_accounts") as usize
}

// Shorthands for the program's own accounts.
pub fn config() -> &'static Layout {
    layout("Config")
}
pub fn buyback_state() -> &'static Layout {
    layout("BuybackState")
}
pub fn harvest_params() -> &'static Layout {
    layout("HarvestParams")
}
pub fn inflow_params() -> &'static Layout {
    layout("InflowParams")
}
pub fn harvest_preview() -> &'static Layout {
    layout("HarvestPreview")
}
