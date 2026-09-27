// Copyright (c) 2026 prt1sn. All rights reserved.
//! Mainnet fixtures written by `tests/fixtures/buyback/fetch.mjs`: program
//! binaries (`programs/<name>.so`) and one account snapshot
//! (`accounts.json`, base64 data). Loaded once per test process.
//!
//! Location: `$SIJKA_BB_FIXTURES`, else `<workspace>/target/buyback-fixtures`.
//! Our program: `$SIJKA_VAULT_SO`, else `<workspace>/target/deploy/sijka_vault.so`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use solana_account::Account;
use solana_pubkey::Pubkey;

/// One mainnet account of the snapshot.
#[derive(Clone, Debug)]
pub struct Snap {
    pub pubkey: Pubkey,
    pub label: String,
    pub account: Account,
}

pub struct Fixtures {
    pub dir: PathBuf,
    /// Slot of the snapshot.
    pub slot: u64,
    pub accounts: Vec<Snap>,
    by_key: HashMap<Pubkey, usize>,
    by_label: HashMap<String, usize>,
    /// Keys the fetcher asked for that do not exist on mainnet.
    pub missing: Vec<(Pubkey, String)>,
    pub programs: HashMap<&'static str, Vec<u8>>,
    pub sijka_so: Vec<u8>,
}

impl Fixtures {
    pub fn get(&self, k: &Pubkey) -> Option<&Snap> {
        self.by_key.get(k).map(|i| &self.accounts[*i])
    }

    pub fn by_label(&self, label: &str) -> Option<&Snap> {
        self.by_label.get(label).map(|i| &self.accounts[*i])
    }

    /// Key of a labelled account (present or known-missing).
    pub fn key(&self, label: &str) -> Pubkey {
        if let Some(s) = self.by_label(label) {
            return s.pubkey;
        }
        self.missing
            .iter()
            .find(|(_, l)| l == label)
            .map(|(k, _)| *k)
            .unwrap_or_else(|| panic!("fixture label not found: {label}"))
    }

    pub fn program(&self, name: &str) -> &[u8] {
        self.programs.get(name).unwrap_or_else(|| panic!("fixture program missing: {name}"))
    }
}

pub fn required() -> bool {
    let on = |k: &str| matches!(std::env::var(k).as_deref(), Ok("1") | Ok("true"));
    on("SIJKA_REQUIRE_SO") || on("RISE_SDK_LOCALNET_REQUIRE_PROGRAMS")
}

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sijka_so_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SIJKA_VAULT_SO") {
        return Some(PathBuf::from(p)).filter(|p| p.exists());
    }
    let p = workspace().join("target/deploy/sijka_vault.so");
    p.exists().then_some(p)
}

fn fixtures_dir() -> PathBuf {
    std::env::var("SIJKA_BB_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace().join("target/buyback-fixtures"))
}

static FX: OnceLock<Option<Fixtures>> = OnceLock::new();

/// The fixtures, or `None` (test skipped) when they are absent and not required.
pub fn fx() -> Option<&'static Fixtures> {
    FX.get_or_init(|| match load() {
        Ok(f) => Some(f),
        Err(e) if required() => panic!("buyback fixtures required but unavailable: {e}"),
        Err(e) => {
            eprintln!("skipping buyback LiteSVM tests: {e}");
            None
        }
    })
    .as_ref()
}

const PROGRAM_NAMES: [&str; 6] = ["pump", "pump_amm", "pump_fees", "token_2022", "spl_token", "associated_token"];

fn load() -> Result<Fixtures, String> {
    let so = sijka_so_path().ok_or("sijka_vault.so not built (cargo build-sbf or SIJKA_VAULT_SO)")?;
    let sijka_so = std::fs::read(&so).map_err(|e| format!("{}: {e}", so.display()))?;
    let dir = fixtures_dir();
    let json_path = dir.join("accounts.json");
    let text = std::fs::read_to_string(&json_path).map_err(|e| {
        format!("{}: {e} (run node programs/sijka-vault/tests/fixtures/buyback/fetch.mjs)", json_path.display())
    })?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("accounts.json: {e}"))?;
    let slot = v["slot"].as_u64().ok_or("accounts.json: slot")?;
    let mut accounts = Vec::new();
    for a in v["accounts"].as_array().ok_or("accounts.json: accounts")? {
        let pubkey = parse_key(a["pubkey"].as_str().ok_or("pubkey")?)?;
        let owner = parse_key(a["owner"].as_str().ok_or("owner")?)?;
        let data = b64decode(a["data"].as_str().ok_or("data")?)?;
        accounts.push(Snap {
            pubkey,
            label: a["label"].as_str().unwrap_or("").to_string(),
            account: Account {
                lamports: a["lamports"].as_u64().ok_or("lamports")?,
                data,
                owner,
                executable: a["executable"].as_bool().unwrap_or(false),
                rent_epoch: u64::MAX,
            },
        });
    }
    let mut missing = Vec::new();
    for m in v["missing"].as_array().ok_or("accounts.json: missing")? {
        missing
            .push((parse_key(m["pubkey"].as_str().ok_or("pubkey")?)?, m["label"].as_str().unwrap_or("").to_string()));
    }
    let by_key = accounts.iter().enumerate().map(|(i, s)| (s.pubkey, i)).collect();
    let by_label = accounts.iter().enumerate().map(|(i, s)| (s.label.clone(), i)).collect();
    let mut programs = HashMap::new();
    for n in PROGRAM_NAMES {
        let p = dir.join("programs").join(format!("{n}.so"));
        programs.insert(n, std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?);
    }
    Ok(Fixtures { dir, slot, accounts, by_key, by_label, missing, programs, sijka_so })
}

pub fn parse_key(s: &str) -> Result<Pubkey, String> {
    s.parse::<Pubkey>().map_err(|e| format!("bad pubkey {s}: {e:?}"))
}

/// Standard base64 (with padding) decoder.
pub fn b64decode(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        let mut n = 0;
        for &c in chunk {
            if c == b'=' {
                break;
            }
            acc = (acc << 6) | val(c).ok_or_else(|| format!("bad base64 char {c}"))?;
            n += 1;
        }
        match n {
            4 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]),
            3 => {
                acc <<= 6;
                out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8]);
            }
            2 => {
                acc <<= 12;
                out.push((acc >> 16) as u8);
            }
            0 => {}
            _ => return Err("bad base64 length".into()),
        }
    }
    Ok(out)
}

#[test]
fn base64_roundtrip_vectors() {
    assert_eq!(b64decode("").unwrap(), b"");
    assert_eq!(b64decode("Zg==").unwrap(), b"f");
    assert_eq!(b64decode("Zm8=").unwrap(), b"fo");
    assert_eq!(b64decode("Zm9v").unwrap(), b"foo");
    assert_eq!(b64decode("Zm9vYmFy").unwrap(), b"foobar");
    assert_eq!(b64decode("U0pLRVZDSEs=").unwrap(), b"SJKEVCHK");
}
