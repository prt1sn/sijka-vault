// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 1 `set_token_mint` (SPEC §5.1.1; TA-10; U-9, U-26): the SIJKA mint and
//! the pump_fees `SharingConfig` v2 that routes 100% of the creator fee to
//! `fee_inbox`. Synthetic accounts cover every rejection; a live pump.fun
//! mint and its live `SharingConfig` (dumped from mainnet in CI by
//! `tests/fixtures/phoenix_core_fetch.sh`) check the offsets on real bytes.

use serde_json::Value;
use solana_pubkey::Pubkey;

use crate::abi;
use crate::harness::*;

const SHARING_CONFIG_DISC: [u8; 8] = [216, 74, 9, 0, 56, 140, 93, 75];
/// Live pump.fun coin with a locked single-shareholder fee sharing config
/// (docs/research/04 app. A, `simcto.cjs`).
pub const LIVE_MINT: &str = "CpgnBP6XLaV6GKfiFYjvyhdA7pCpB1KQopqkz5dSpump";
pub const LIVE_SHARING_CONFIG: &str = "K2b5hhfphG9UQFtRgZbmd7q4LVDSP1R7Hmog2sNzk4w";

/// SPL mint base (82 bytes): authorities as COption tags.
fn mint_base(mint_auth: bool, freeze: bool, decimals: u8) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    if mint_auth {
        d[0..4].copy_from_slice(&1u32.to_le_bytes());
        d[4..36].copy_from_slice(Pubkey::new_unique().as_ref());
    }
    d[36..44].copy_from_slice(&1_000_000_000_000_000u64.to_le_bytes());
    d[44] = decimals;
    d[45] = 1;
    if freeze {
        d[46..50].copy_from_slice(&1u32.to_le_bytes());
        d[50..82].copy_from_slice(Pubkey::new_unique().as_ref());
    }
    d
}

/// Token-2022 mint: base, padding to 165, account type 1 at 165, TLV at 166.
pub fn t22_mint(mint_auth: bool, freeze: bool, exts: &[(u16, usize)]) -> Vec<u8> {
    let mut d = mint_base(mint_auth, freeze, 6);
    d.resize(165, 0);
    d.push(1);
    for (ty, len) in exts {
        d.extend_from_slice(&ty.to_le_bytes());
        d.extend_from_slice(&(*len as u16).to_le_bytes());
        d.extend(std::iter::repeat_n(0xAB, *len));
    }
    d
}

/// The live pump.fun mint shape: MetadataPointer (18, 64) + TokenMetadata (19, 170).
pub fn pump_like_mint() -> Vec<u8> {
    t22_mint(false, false, &[(18, 64), (19, 170)])
}

pub struct Sc {
    pub version: u8,
    pub status: u8,
    pub admin_revoked: u8,
    pub holders: Vec<(Pubkey, u16)>,
}

pub fn sharing_config_data(mint: &Pubkey, bump: u8, sc: &Sc) -> Vec<u8> {
    let mut d = vec![0u8; 1024];
    d[0..8].copy_from_slice(&SHARING_CONFIG_DISC);
    d[8] = bump;
    d[9] = sc.version;
    d[10] = sc.status;
    d[11..43].copy_from_slice(mint.as_ref());
    d[43..75].copy_from_slice(Pubkey::new_unique().as_ref());
    d[75] = sc.admin_revoked;
    d[76..80].copy_from_slice(&(sc.holders.len() as u32).to_le_bytes());
    for (i, (k, bps)) in sc.holders.iter().enumerate() {
        let o = 80 + 34 * i;
        d[o..o + 32].copy_from_slice(k.as_ref());
        d[o + 32..o + 34].copy_from_slice(&bps.to_le_bytes());
    }
    d
}

pub fn sharing_config_pda(mint: &Pubkey) -> (Pubkey, u8) {
    find_pda(&[b"sharing-config", mint.as_ref()], &PUMP_FEES)
}

impl Env {
    /// Install a mint (owner `token_program`) and its SharingConfig PDA.
    pub fn install_coin(&mut self, token_program: &Pubkey, mint_data: Vec<u8>, sc: &Sc) -> (Pubkey, Pubkey) {
        let mint = Pubkey::new_unique();
        self.install(&mint, token_program, mint_data);
        let (key, bump) = sharing_config_pda(&mint);
        self.install(&key, &PUMP_FEES, sharing_config_data(&mint, bump, sc));
        (mint, key)
    }

    pub fn good_sc(&self) -> Sc {
        Sc { version: 2, status: 1, admin_revoked: 1, holders: vec![(self.pdas.fee_inbox.0, 10_000)] }
    }

    /// A valid pump-like Token-2022 coin set as the SIJKA mint.
    pub fn set_valid_token_mint(&mut self) -> Pubkey {
        let sc = self.good_sc();
        let (mint, key) = self.install_coin(&TOKEN_2022, pump_like_mint(), &sc);
        ok(self.send1(self.set_token_mint_ix(&self.admin, &mint, &key), S_ADMIN), "set_token_mint");
        mint
    }
}

#[test]
fn set_token_mint_token2022_pump_layout() {
    let Some(mut env) = Env::new() else { return };
    env.initialize();
    let sc = env.good_sc();
    let (mint, key) = env.install_coin(&TOKEN_2022, pump_like_mint(), &sc);
    let (_, ts) = env.clock();
    let m = ok(env.send1(env.set_token_mint_ix(&env.admin, &mint, &key), S_ADMIN), "set_token_mint");
    assert_eq!(env.cfg_key("token_mint"), mint);
    assert_eq!(env.cfg_key("token_program"), TOKEN_2022);
    assert_eq!(env.cfg_u8("token_decimals"), 6);
    assert_eq!(env.cfg_key("buyback_token"), ata(&env.pdas.buyback_authority.0, &mint, &TOKEN_2022));
    assert_eq!(env.cfg_i64("token_mint_set_ts"), ts);
    let ev = one_event(&m.logs, "SJKEVMNT");
    let e = abi::event("SJKEVMNT");
    assert_eq!(key_of(e.key(&ev, "token_mint")), mint);
    assert_eq!(key_of(e.key(&ev, "sharing_config")), key);
    assert_eq!(e.u8(&ev, "decimals"), 6);
    // Written once.
    let sc = env.good_sc();
    let (mint2, key2) = env.install_coin(&TOKEN_2022, pump_like_mint(), &sc);
    expect_err(
        env.send1(env.set_token_mint_ix(&env.admin, &mint2, &key2), S_ADMIN),
        "TokenMintAlreadySet",
        "second mint",
    );
}

#[test]
fn set_token_mint_rejects_unsafe_mints_and_configs() {
    let Some(mut env) = Env::new() else { return };
    env.initialize();
    let fee_inbox = env.pdas.fee_inbox.0;
    // Mint checks (SPEC §5.1.1 step 2, U-26).
    let mut truncated = pump_like_mint();
    truncated.truncate(truncated.len() - 10);
    let mut partial_header = pump_like_mint();
    partial_header.extend_from_slice(&[18, 0]);
    let mut not_init = pump_like_mint();
    not_init[45] = 0;
    let mut wrong_type = pump_like_mint();
    wrong_type[165] = 2;
    let mut spl_long = mint_base(false, false, 6);
    spl_long.push(0);
    let bad_mints: Vec<(&str, Pubkey, Vec<u8>)> = vec![
        ("mint authority Some", TOKEN_2022, t22_mint(true, false, &[(18, 64), (19, 170)])),
        ("freeze authority Some", TOKEN_2022, t22_mint(false, true, &[(18, 64), (19, 170)])),
        ("TransferFeeConfig (1)", TOKEN_2022, t22_mint(false, false, &[(1, 108), (18, 64)])),
        ("PermanentDelegate (12)", TOKEN_2022, t22_mint(false, false, &[(18, 64), (12, 32)])),
        ("TransferHook (14)", TOKEN_2022, t22_mint(false, false, &[(14, 64)])),
        ("NonTransferable (9)", TOKEN_2022, t22_mint(false, false, &[(9, 0)])),
        ("Pausable (26)", TOKEN_2022, t22_mint(false, false, &[(26, 33)])),
        ("MintCloseAuthority (6)", TOKEN_2022, t22_mint(false, false, &[(6, 32)])),
        ("truncated TLV", TOKEN_2022, truncated),
        ("partial TLV header", TOKEN_2022, partial_header),
        ("not initialized", TOKEN_2022, not_init),
        ("account type not Mint", TOKEN_2022, wrong_type),
        ("SPL mint of 83 bytes", SPL_TOKEN, spl_long),
        ("owner System", SYSTEM_PROGRAM, mint_base(false, false, 6)),
    ];
    for (label, owner, data) in bad_mints {
        let sc = env.good_sc();
        let (mint, key) = env.install_coin(&owner, data, &sc);
        expect_err(env.send1(env.set_token_mint_ix(&env.admin, &mint, &key), S_ADMIN), "InvalidTokenMint", label);
    }
    // SharingConfig checks (step 3, U-9).
    let other = Pubkey::new_unique();
    let bad_sc: Vec<(&str, Sc)> = vec![
        ("version 1", Sc { version: 1, ..env.good_sc() }),
        ("status Paused", Sc { status: 0, ..env.good_sc() }),
        ("admin not revoked", Sc { admin_revoked: 0, ..env.good_sc() }),
        ("two shareholders", Sc { holders: vec![(fee_inbox, 9_999), (other, 1)], ..env.good_sc() }),
        ("bps 9999", Sc { holders: vec![(fee_inbox, 9_999)], ..env.good_sc() }),
        ("foreign shareholder", Sc { holders: vec![(other, 10_000)], ..env.good_sc() }),
        ("no shareholders", Sc { holders: vec![], ..env.good_sc() }),
    ];
    for (label, sc) in bad_sc {
        let (mint, key) = env.install_coin(&TOKEN_2022, pump_like_mint(), &sc);
        expect_err(env.send1(env.set_token_mint_ix(&env.admin, &mint, &key), S_ADMIN), "InvalidSharingConfig", label);
    }
    // Config of another mint, a config off the PDA, wrong owner, wrong discriminator.
    let sc = env.good_sc();
    let (mint_a, key_a) = env.install_coin(&TOKEN_2022, pump_like_mint(), &sc);
    let (mint_b, _) = env.install_coin(&TOKEN_2022, pump_like_mint(), &sc);
    expect_err(
        env.send1(env.set_token_mint_ix(&env.admin, &mint_b, &key_a), S_ADMIN),
        "InvalidSharingConfig",
        "config of another mint",
    );
    let off_pda = Pubkey::new_unique();
    let (_, bump_a) = sharing_config_pda(&mint_a);
    env.install(&off_pda, &PUMP_FEES, sharing_config_data(&mint_a, bump_a, &sc));
    expect_err(
        env.send1(env.set_token_mint_ix(&env.admin, &mint_a, &off_pda), S_ADMIN),
        "InvalidSharingConfig",
        "config off the PDA",
    );
    let mut wrong_bump = sharing_config_data(&mint_a, bump_a, &sc);
    wrong_bump[8] = bump_a.wrapping_sub(1);
    env.install(&key_a, &PUMP_FEES, wrong_bump);
    expect_err(
        env.send1(env.set_token_mint_ix(&env.admin, &mint_a, &key_a), S_ADMIN),
        "InvalidSharingConfig",
        "stored bump not canonical",
    );
    env.install(&key_a, &SYSTEM_PROGRAM, sharing_config_data(&mint_a, bump_a, &sc));
    expect_err(
        env.send1(env.set_token_mint_ix(&env.admin, &mint_a, &key_a), S_ADMIN),
        "InvalidSharingConfig",
        "owner not pump_fees",
    );
    let mut bad_disc = sharing_config_data(&mint_a, bump_a, &sc);
    bad_disc[0] ^= 1;
    env.install(&key_a, &PUMP_FEES, bad_disc);
    expect_err(
        env.send1(env.set_token_mint_ix(&env.admin, &mint_a, &key_a), S_ADMIN),
        "InvalidSharingConfig",
        "discriminator",
    );
    // Admin only.
    env.install(&key_a, &PUMP_FEES, sharing_config_data(&mint_a, bump_a, &sc));
    expect_err(
        env.send1(env.set_token_mint_ix(&env.attacker, &mint_a, &key_a), S_ATTACKER),
        "Unauthorized",
        "attacker",
    );
    assert_eq!(env.cfg_key("token_mint"), Pubkey::default(), "nothing written");
    // Legacy SPL Token coin (82 bytes) passes.
    let (mint, key) = env.install_coin(&SPL_TOKEN, mint_base(false, false, 6), &sc);
    ok(env.send1(env.set_token_mint_ix(&env.admin, &mint, &key), S_ADMIN), "SPL Token mint");
    assert_eq!(env.cfg_key("token_program"), SPL_TOKEN);
    assert_eq!(env.cfg_key("buyback_token"), ata(&env.pdas.buyback_authority.0, &mint, &SPL_TOKEN));
}

/// `solana account --output json` dump → (owner, data).
fn load_dump(dir: &str, key: &str) -> Option<(Pubkey, Vec<u8>)> {
    let text = std::fs::read_to_string(format!("{dir}/{key}.json")).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let acc = &v["account"];
    let owner: Pubkey = acc["owner"].as_str()?.parse().ok()?;
    let b64 = acc["data"][0].as_str()?;
    Some((owner, b64_decode(b64)?))
}

/// U-9 / U-26 on real mainnet bytes: the live pump.fun Token-2022 mint and
/// its live `SharingConfig` v2. Offsets (bump @8, version @9, status @10,
/// mint @11, admin_revoked @75, count @76, first holder @80..114) and the PDA
/// seeds are checked on the dump; `set_token_mint` rejects it as is (the
/// shareholder is not our `fee_inbox`) and accepts it with only the
/// shareholder address replaced.
#[test]
fn set_token_mint_on_live_mainnet_dumps() {
    let Some(mut env) = Env::new() else { return };
    let dir = std::env::var("SIJKA_PHOENIX_CORE_FIXTURES").unwrap_or_default();
    let (Some((mint_owner, mint_data)), Some((sc_owner, sc_data))) =
        (load_dump(&dir, LIVE_MINT), load_dump(&dir, LIVE_SHARING_CONFIG))
    else {
        if env_on("SIJKA_REQUIRE_FIXTURES") {
            panic!("live dumps missing in {dir:?} (tests/fixtures/phoenix_core_fetch.sh)");
        }
        eprintln!("skipping: live mainnet dumps not present (SIJKA_PHOENIX_CORE_FIXTURES)");
        return;
    };
    let mint: Pubkey = LIVE_MINT.parse().unwrap();
    let key: Pubkey = LIVE_SHARING_CONFIG.parse().unwrap();
    eprintln!("live mint: owner {mint_owner}, {} bytes", mint_data.len());
    // TLV walk of the live mint (U-26).
    let mut tlv = Vec::new();
    if mint_data.len() > 166 {
        let mut o = 166;
        while o + 4 <= mint_data.len() {
            let ty = u16::from_le_bytes([mint_data[o], mint_data[o + 1]]);
            let l = u16::from_le_bytes([mint_data[o + 2], mint_data[o + 3]]) as usize;
            if ty == 0 {
                break;
            }
            tlv.push((ty, l));
            o += 4 + l;
        }
    }
    eprintln!("live mint TLV (type, len): {tlv:?}; mint authority tag {}, freeze tag {}", mint_data[0], mint_data[46]);
    assert_eq!(sc_owner, PUMP_FEES, "SharingConfig owner");
    assert_eq!(sc_data[0..8], SHARING_CONFIG_DISC, "SharingConfig discriminator");
    assert_eq!(&sc_data[11..43], mint.as_ref(), "mint @11");
    let (pda, bump) = sharing_config_pda(&mint);
    assert_eq!(pda, key, "PDA([\"sharing-config\", mint], pump_fees)");
    assert_eq!(sc_data[8], bump, "bump @8 is the canonical bump");
    let count = u32::from_le_bytes(sc_data[76..80].try_into().unwrap());
    eprintln!(
        "live SharingConfig: {} bytes, version {}, status {}, admin_revoked {}, shareholders {count}, first bps {}",
        sc_data.len(),
        sc_data[9],
        sc_data[10],
        sc_data[75],
        u16::from_le_bytes([sc_data[112], sc_data[113]])
    );
    assert_eq!(sc_data[9], 2, "U-9: version 2 at @9");

    env.initialize();
    env.install(&mint, &mint_owner, mint_data);
    env.install(&key, &PUMP_FEES, sc_data.clone());
    expect_err(
        env.send1(env.set_token_mint_ix(&env.admin, &mint, &key), S_ADMIN),
        "InvalidSharingConfig",
        "live config, foreign shareholder",
    );
    let mut patched = sc_data;
    patched[80..112].copy_from_slice(env.pdas.fee_inbox.0.as_ref());
    env.install(&key, &PUMP_FEES, patched);
    let r = env.send1(env.set_token_mint_ix(&env.admin, &mint, &key), S_ADMIN);
    ok(r, "live mint + live config with our fee_inbox as the only shareholder");
    assert_eq!(env.cfg_key("token_mint"), mint);
    assert_eq!(env.cfg_key("token_program"), mint_owner);
}
