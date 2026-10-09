// Copyright (c) 2026 prt1sn. All rights reserved.
//! Instructions around pump / pump_amm: our chunks (tags 44, 45, SPEC §5.5.3
//! tables) and direct trades of an outside "market" wallet on the same
//! accounts (IDL `pump.json` `buy_exact_quote_in_v2` / `sell_v2`,
//! `pump_amm.json` `buy_exact_quote_in` / `sell`), pump `migrate_v2`,
//! `distribute_creator_fees_v2`.

use sijka_vault::constants as c;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::harness::*;

pub const IX_PUMP_BUY_EXACT_QUOTE_IN_V2: [u8; 8] = c::IX_BUY_EXACT_QUOTE_IN_V2;
pub const IX_PUMP_SELL_V2: [u8; 8] = [93, 246, 130, 60, 231, 233, 64, 178];
pub const IX_PUMP_BUY_V2: [u8; 8] = [184, 23, 238, 97, 103, 197, 211, 61];
pub const IX_PUMP_MIGRATE_V2: [u8; 8] = [187, 203, 18, 31, 206, 237, 254, 41];
pub const IX_PUMP_DISTRIBUTE_V2: [u8; 8] = [255, 203, 19, 79, 244, 68, 8, 159];
pub const IX_AMM_BUY_EXACT_QUOTE_IN: [u8; 8] = c::IX_AMM_BUY_EXACT_QUOTE_IN;
pub const IX_AMM_BUY_EXACT_QUOTE_IN_V2: [u8; 8] = [194, 171, 28, 70, 104, 77, 91, 47];
pub const IX_AMM_SELL: [u8; 8] = [51, 230, 133, 164, 1, 127, 131, 173];

/// Fee recipients taken from the live pump `Global` / pump_amm `GlobalConfig`
/// snapshots (pump checks them itself, U-29).
#[derive(Clone, Debug)]
pub struct Recips {
    pub fee_recipient: Pubkey,
    pub buyback_fee_recipient: Pubkey,
    pub amm_protocol: Pubkey,
    pub amm_buyback: Pubkey,
}

impl Recips {
    pub fn pick(v: &Vault) -> Recips {
        let q = v.coin().quote_mint;
        let g = v.data(&pk(c::PUMP_GLOBAL));
        let gc = v.data(&pk(c::AMM_GLOBAL_CONFIG));
        let has_ata = |k: &Pubkey| v.exists(&ata(k, &tokenkeg(), &q));
        let fee_recipient = key_at(&g, 41);
        let buybacks: Vec<Pubkey> = (0..8).map(|i| key_at(&g, 741 + 32 * i)).collect();
        let buyback_fee_recipient = *buybacks.iter().find(|k| has_ata(k)).unwrap_or(&buybacks[0]);
        let protos: Vec<Pubkey> = (0..8).map(|i| key_at(&gc, 57 + 32 * i)).collect();
        let amm_protocol = *protos.iter().find(|k| has_ata(k)).expect("an AMM protocol fee recipient with a quote ATA");
        let amm_bbs: Vec<Pubkey> = (0..8).map(|i| key_at(&gc, 643 + 32 * i)).collect();
        let amm_buyback = *amm_bbs.iter().find(|k| has_ata(k)).expect("an AMM buyback fee recipient with a quote ATA");
        Recips { fee_recipient, buyback_fee_recipient, amm_protocol, amm_buyback }
    }

    pub fn global_fee_recipients(v: &Vault) -> Vec<Pubkey> {
        let g = v.data(&pk(c::PUMP_GLOBAL));
        let mut out = vec![key_at(&g, 41)];
        out.extend((0..7).map(|i| key_at(&g, 162 + 32 * i)));
        out
    }

    pub fn global_buyback_recipients(v: &Vault) -> Vec<Pubkey> {
        let g = v.data(&pk(c::PUMP_GLOBAL));
        (0..8).map(|i| key_at(&g, 741 + 32 * i)).collect()
    }
}

/// `BondingCurve.creator` (@49) and `Pool.coin_creator` (@211) as they are now.
pub fn live_creator(v: &Vault) -> Pubkey {
    key_at(&v.data(&v.coin().curve), 49)
}
pub fn live_coin_creator(v: &Vault) -> Pubkey {
    key_at(&v.data(&v.coin().pool), 211)
}

pub fn pump_uva(user: &Pubkey) -> Pubkey {
    pda(&[b"user_volume_accumulator", user.as_ref()], &pump())
}
pub fn amm_uva(user: &Pubkey) -> Pubkey {
    pda(&[b"user_volume_accumulator", user.as_ref()], &pump_amm())
}

fn w(k: Pubkey) -> AccountMeta {
    AccountMeta::new(k, false)
}
fn r(k: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(k, false)
}

/// The 27 pump accounts of `buy_exact_quote_in_v2` / our tag 44 for `user`.
pub fn curve_buy_accounts(
    v: &Vault,
    user: &Pubkey,
    user_base: &Pubkey,
    user_quote: &Pubkey,
    rc: &Recips,
) -> Vec<AccountMeta> {
    let ck = v.coin();
    let q = ck.quote_mint;
    let (cv, cv_ata) = ck.creator_vault_for(&live_creator(v));
    let uva = pump_uva(user);
    vec![
        r(pk(c::PUMP_GLOBAL)),
        w(ck.mint),
        r(q),
        r(ck.token_program),
        r(tokenkeg()),
        r(pk(c::ATA_PROGRAM_ID)),
        w(rc.fee_recipient),
        w(ata(&rc.fee_recipient, &tokenkeg(), &q)),
        w(rc.buyback_fee_recipient),
        w(ata(&rc.buyback_fee_recipient, &tokenkeg(), &q)),
        w(ck.curve),
        w(ck.curve_base_ata),
        w(ck.curve_quote_ata),
        w(*user),
        w(*user_base),
        w(*user_quote),
        w(cv),
        w(cv_ata),
        r(ck.sharing_config),
        r(pk(c::PUMP_GVA)),
        w(uva),
        w(ata(&uva, &tokenkeg(), &q)),
        r(pk(c::PUMP_FEE_CONFIG)),
        r(pump_fees()),
        r(system()),
        r(pk(c::PUMP_EVENT_AUTHORITY)),
        r(pump()),
    ]
}

/// The keeper signer after the pump block of tags 44 / 45 (SPEC v4: #31 on
/// the curve, #30 on PumpSwap).
pub fn keeper_meta(v: &Vault) -> AccountMeta {
    AccountMeta::new_readonly(v.keeper.pubkey(), true)
}

/// Tag 44 `bb_chunk_curve` with the accounts a keeper passes (SPEC §5.5.8).
/// SPEC v4: `min_out` is the keeper's (the only price limit); the harness
/// turns `0` into the permissive keeper floor `1` (a real keeper quotes the
/// live reserves, see `t_curve::chunk_with_a_keeper_quote`). Use
/// [`chunk_curve_ix_raw`] to send `min_out = 0` itself.
pub fn chunk_curve_ix(v: &Vault, max_quote_in: u64, min_out: u64) -> Instruction {
    let rc = Recips::pick(v);
    chunk_curve_ix_with(v, max_quote_in, min_out, &rc)
}

pub fn chunk_curve_ix_with(v: &Vault, max_quote_in: u64, min_out: u64, rc: &Recips) -> Instruction {
    chunk_curve_ix_raw(v, max_quote_in, min_out.max(1), rc)
}

pub fn chunk_curve_ix_raw(v: &Vault, max_quote_in: u64, min_out: u64, rc: &Recips) -> Instruction {
    let mut d = vec![44u8];
    d.extend_from_slice(&max_quote_in.to_le_bytes());
    d.extend_from_slice(&min_out.to_le_bytes());
    let mut accounts = vec![w(v.k.buyback_state), r(v.k.config), r(ix_sysvar()), r(dont_front())];
    accounts.extend(curve_buy_accounts(v, &v.k.buyback_authority, &v.buyback_token(), &v.bb_quote(), rc));
    accounts.push(keeper_meta(v));
    v.ix(d, accounts)
}

/// The 23 + 3 pump_amm accounts of `buy_exact_quote_in` / our tag 45.
pub fn amm_buy_accounts(
    v: &Vault,
    user: &Pubkey,
    user_base: &Pubkey,
    user_quote: &Pubkey,
    rc: &Recips,
) -> Vec<AccountMeta> {
    let ck = v.coin();
    let q = ck.quote_mint;
    let (ccva, ccv_ata) = ck.coin_creator_vault_for(&live_coin_creator(v));
    vec![
        w(ck.pool),
        w(*user),
        r(pk(c::AMM_GLOBAL_CONFIG)),
        w(ck.mint),
        r(q),
        w(*user_base),
        w(*user_quote),
        w(ck.pool_base_ta),
        w(ck.pool_quote_ta),
        r(rc.amm_protocol),
        w(ata(&rc.amm_protocol, &tokenkeg(), &q)),
        r(ck.token_program),
        r(tokenkeg()),
        r(system()),
        r(pk(c::ATA_PROGRAM_ID)),
        r(pk(c::AMM_EVENT_AUTHORITY)),
        r(pump_amm()),
        w(ccv_ata),
        r(ccva),
        r(pk(c::AMM_GVA)),
        w(amm_uva(user)),
        r(pk(c::AMM_FEE_CONFIG)),
        r(pump_fees()),
        r(ck.pool_v2),
        r(rc.amm_buyback),
        w(ata(&rc.amm_buyback, &tokenkeg(), &q)),
    ]
}

/// Tag 45 `bb_chunk_amm` (SPEC §5.5.9); `min_out` as in [`chunk_curve_ix`].
pub fn chunk_amm_ix(v: &Vault, max_quote_in: u64, min_out: u64) -> Instruction {
    let rc = Recips::pick(v);
    chunk_amm_ix_with(v, max_quote_in, min_out, &rc)
}

pub fn chunk_amm_ix_with(v: &Vault, max_quote_in: u64, min_out: u64, rc: &Recips) -> Instruction {
    chunk_amm_ix_raw(v, max_quote_in, min_out.max(1), rc)
}

pub fn chunk_amm_ix_raw(v: &Vault, max_quote_in: u64, min_out: u64, rc: &Recips) -> Instruction {
    let mut d = vec![45u8];
    d.extend_from_slice(&max_quote_in.to_le_bytes());
    d.extend_from_slice(&min_out.to_le_bytes());
    let mut accounts = vec![w(v.k.buyback_state), r(v.k.config), r(ix_sysvar()), r(dont_front())];
    accounts.extend(amm_buy_accounts(v, &v.k.buyback_authority, &v.buyback_token(), &v.bb_quote(), rc));
    accounts.push(keeper_meta(v));
    v.ix(d, accounts)
}

// ------------------------------------------------------------ market ----

/// An outside wallet trading the coin directly on pump / pump_amm.
pub struct Trader {
    pub kp: Keypair,
}

impl Trader {
    /// New funded wallet with its base ATA and (quote) ATA created.
    pub fn new(v: &mut Vault, lamports: u64) -> Trader {
        let kp = Keypair::new();
        v.svm.airdrop(&kp.pubkey(), lamports).unwrap();
        let ck = v.coin().clone();
        let ixs = vec![
            create_ata_ix(&kp.pubkey(), &kp.pubkey(), &ck.mint, &ck.token_program),
            create_ata_ix(&kp.pubkey(), &kp.pubkey(), &ck.quote_mint, &tokenkeg()),
        ];
        ok(v.send(ixs, &[&kp]));
        Trader { kp }
    }

    pub fn pubkey(&self) -> Pubkey {
        self.kp.pubkey()
    }

    pub fn base_ata(&self, v: &Vault) -> Pubkey {
        let ck = v.coin();
        ata(&self.pubkey(), &ck.token_program, &ck.mint)
    }

    pub fn quote_ata(&self, v: &Vault) -> Pubkey {
        ata(&self.pubkey(), &tokenkeg(), &v.coin().quote_mint)
    }

    pub fn base(&self, v: &Vault) -> u64 {
        v.token_amount(&self.base_ata(v))
    }

    /// Give the wallet `amount` USDC (USDC pair).
    pub fn fund_usdc(&self, v: &mut Vault, amount: u64) {
        let a = self.quote_ata(v);
        v.set_token_account(a, tokenkeg(), usdc(), self.pubkey(), amount);
    }

    /// Wrap `lamports` into the wallet's wSOL ATA (AMM trades on SOL pools).
    pub fn wrap(&self, v: &mut Vault, lamports: u64) {
        let a = self.quote_ata(v);
        let ixs = vec![system_transfer_ix(&self.pubkey(), &a, lamports), sync_native_ix(&a)];
        let kp = self.kp.insecure_clone();
        ok(v.send(ixs, &[&kp]));
    }

    pub fn curve_buy_ix(&self, v: &Vault, spendable: u64, min_out: u64) -> Instruction {
        let rc = Recips::pick(v);
        let mut d = IX_PUMP_BUY_EXACT_QUOTE_IN_V2.to_vec();
        d.extend_from_slice(&spendable.to_le_bytes());
        d.extend_from_slice(&min_out.to_le_bytes());
        let mut accounts = curve_buy_accounts(v, &self.pubkey(), &self.base_ata(v), &self.quote_ata(v), &rc);
        accounts[13] = AccountMeta::new(self.pubkey(), true);
        Instruction { program_id: pump(), accounts, data: d }
    }

    /// pump `buy_v2(amount, max_sol_cost)`: an exact token amount.
    pub fn curve_buy_tokens_ix(&self, v: &Vault, amount: u64, max_cost: u64) -> Instruction {
        let mut ix = self.curve_buy_ix(v, 0, 0);
        let mut d = IX_PUMP_BUY_V2.to_vec();
        d.extend_from_slice(&amount.to_le_bytes());
        d.extend_from_slice(&max_cost.to_le_bytes());
        ix.data = d;
        ix
    }

    pub fn curve_buy(&self, v: &mut Vault, spendable: u64) -> litesvm::types::TransactionResult {
        let ix = self.curve_buy_ix(v, spendable, 1);
        let kp = self.kp.insecure_clone();
        v.send(vec![ix], &[&kp])
    }

    pub fn curve_sell_ix(&self, v: &Vault, amount: u64, min_out: u64) -> Instruction {
        let rc = Recips::pick(v);
        let ck = v.coin();
        let q = ck.quote_mint;
        let (cv, cv_ata) = ck.creator_vault_for(&live_creator(v));
        let uva = pump_uva(&self.pubkey());
        let mut d = IX_PUMP_SELL_V2.to_vec();
        d.extend_from_slice(&amount.to_le_bytes());
        d.extend_from_slice(&min_out.to_le_bytes());
        let accounts = vec![
            r(pk(c::PUMP_GLOBAL)),
            r(ck.mint),
            r(q),
            r(ck.token_program),
            r(tokenkeg()),
            r(pk(c::ATA_PROGRAM_ID)),
            w(rc.fee_recipient),
            w(ata(&rc.fee_recipient, &tokenkeg(), &q)),
            w(rc.buyback_fee_recipient),
            w(ata(&rc.buyback_fee_recipient, &tokenkeg(), &q)),
            w(ck.curve),
            w(ck.curve_base_ata),
            w(ck.curve_quote_ata),
            AccountMeta::new(self.pubkey(), true),
            w(self.base_ata(v)),
            w(self.quote_ata(v)),
            w(cv),
            w(cv_ata),
            r(ck.sharing_config),
            w(uva),
            w(ata(&uva, &tokenkeg(), &q)),
            r(pk(c::PUMP_FEE_CONFIG)),
            r(pump_fees()),
            r(system()),
            r(pk(c::PUMP_EVENT_AUTHORITY)),
            r(pump()),
        ];
        Instruction { program_id: pump(), accounts, data: d }
    }

    pub fn curve_sell(&self, v: &mut Vault, amount: u64) -> litesvm::types::TransactionResult {
        let ix = self.curve_sell_ix(v, amount, 0);
        let kp = self.kp.insecure_clone();
        v.send(vec![ix], &[&kp])
    }

    /// pump_amm `buy_exact_quote_in` from the wallet's quote ATA;
    /// `track_volume` is the `OptionBool` byte.
    pub fn amm_buy_ix(&self, v: &Vault, spendable: u64, min_out: u64, track_volume: u8) -> Instruction {
        let rc = Recips::pick(v);
        let mut d = IX_AMM_BUY_EXACT_QUOTE_IN.to_vec();
        d.extend_from_slice(&spendable.to_le_bytes());
        d.extend_from_slice(&min_out.to_le_bytes());
        d.push(track_volume);
        let mut accounts = amm_buy_accounts(v, &self.pubkey(), &self.base_ata(v), &self.quote_ata(v), &rc);
        accounts[1] = AccountMeta::new(self.pubkey(), true);
        Instruction { program_id: pump_amm(), accounts, data: d }
    }

    pub fn amm_buy(&self, v: &mut Vault, spendable: u64, track_volume: u8) -> litesvm::types::TransactionResult {
        let ix = self.amm_buy_ix(v, spendable, 1, track_volume);
        let kp = self.kp.insecure_clone();
        v.send(vec![ix], &[&kp])
    }

    /// Current PumpSwap v2 buy (official pump_amm IDL): protocol and creator
    /// fees remain in the pool, reducing its signed virtual quote reserves.
    pub fn amm_buy_v2(&self, v: &mut Vault, spendable: u64) -> litesvm::types::TransactionResult {
        let ck = v.coin();
        let rc = Recips::pick(v);
        let mut data = IX_AMM_BUY_EXACT_QUOTE_IN_V2.to_vec();
        data.extend_from_slice(&spendable.to_le_bytes());
        data.extend_from_slice(&1u64.to_le_bytes());
        let accounts = vec![
            w(ck.pool),
            AccountMeta::new(self.pubkey(), true),
            r(pk(c::AMM_GLOBAL_CONFIG)),
            r(ck.mint),
            r(ck.quote_mint),
            w(self.base_ata(v)),
            w(self.quote_ata(v)),
            w(ck.pool_base_ta),
            w(ck.pool_quote_ta),
            r(ck.token_program),
            r(tokenkeg()),
            r(system()),
            w(amm_uva(&self.pubkey())),
            r(pk(c::AMM_FEE_CONFIG)),
            w(ata(&rc.amm_buyback, &tokenkeg(), &ck.quote_mint)),
            r(pk(c::AMM_EVENT_AUTHORITY)),
            r(pump_amm()),
        ];
        let ix = Instruction { program_id: pump_amm(), accounts, data };
        let kp = self.kp.insecure_clone();
        v.send(vec![ix], &[&kp])
    }

    pub fn amm_sell_ix(&self, v: &Vault, amount: u64, min_out: u64) -> Instruction {
        let rc = Recips::pick(v);
        let ck = v.coin();
        let q = ck.quote_mint;
        let (ccva, ccv_ata) = ck.coin_creator_vault_for(&live_coin_creator(v));
        let mut d = IX_AMM_SELL.to_vec();
        d.extend_from_slice(&amount.to_le_bytes());
        d.extend_from_slice(&min_out.to_le_bytes());
        let accounts = vec![
            w(ck.pool),
            AccountMeta::new(self.pubkey(), true),
            r(pk(c::AMM_GLOBAL_CONFIG)),
            r(ck.mint),
            r(q),
            w(self.base_ata(v)),
            w(self.quote_ata(v)),
            w(ck.pool_base_ta),
            w(ck.pool_quote_ta),
            r(rc.amm_protocol),
            w(ata(&rc.amm_protocol, &tokenkeg(), &q)),
            r(ck.token_program),
            r(tokenkeg()),
            r(system()),
            r(pk(c::ATA_PROGRAM_ID)),
            r(pk(c::AMM_EVENT_AUTHORITY)),
            r(pump_amm()),
            w(ccv_ata),
            r(ccva),
            r(pk(c::AMM_FEE_CONFIG)),
            r(pump_fees()),
            r(ck.pool_v2),
            r(rc.amm_buyback),
            w(ata(&rc.amm_buyback, &tokenkeg(), &q)),
        ];
        Instruction { program_id: pump_amm(), accounts, data: d }
    }
}

/// pump `migrate_v2` (IDL order), `user` = `payer`.
pub fn migrate_v2_ix(v: &Vault, payer: &Pubkey) -> Instruction {
    let ck = v.coin();
    let g = v.data(&pk(c::PUMP_GLOBAL));
    let withdraw_authority = key_at(&g, 113);
    let lp_mint = pda(&[b"pool_lp_mint", ck.pool.as_ref()], &pump_amm());
    let accounts = vec![
        r(pk(c::PUMP_GLOBAL)),
        w(withdraw_authority),
        r(ck.mint),
        r(ck.quote_mint),
        w(ck.curve),
        w(ck.curve_base_ata),
        w(ck.curve_quote_ata),
        AccountMeta::new(*payer, true),
        r(system()),
        r(pump_amm()),
        w(ck.pool),
        w(ck.pool_authority),
        w(ata(&ck.pool_authority, &ck.token_program, &ck.mint)),
        w(ata(&ck.pool_authority, &tokenkeg(), &ck.quote_mint)),
        r(pk(c::AMM_GLOBAL_CONFIG)),
        w(lp_mint),
        w(ata(&ck.pool_authority, &t22(), &lp_mint)),
        w(ck.pool_base_ta),
        w(ck.pool_quote_ta),
        r(ck.token_program),
        r(tokenkeg()),
        r(t22()),
        r(pk(c::ATA_PROGRAM_ID)),
        r(pk(c::AMM_EVENT_AUTHORITY)),
        r(key("SysvarRent111111111111111111111111111111111")),
        r(pk(c::PUMP_EVENT_AUTHORITY)),
        r(pump()),
    ];
    // Remaining (pump-sdk 2.0.0 `migrateV2Instruction`): boost vault
    // authority PDA(pump_amm, ["boost_vault", pool]) and its quote ATA.
    let boost = pda(&[b"boost_vault", ck.pool.as_ref()], &pump_amm());
    let mut accounts = accounts;
    accounts.push(r(boost));
    accounts.push(w(ata(&boost, &tokenkeg(), &ck.quote_mint)));
    Instruction { program_id: pump(), accounts, data: IX_PUMP_MIGRATE_V2.to_vec() }
}

/// pump `distribute_creator_fees_v2(initialize_ata)` with the shareholders of
/// the sharing config as remaining accounts (the quote ATA of each for
/// non-SOL quotes).
pub fn distribute_v2_ix(v: &Vault, payer: &Pubkey, initialize_ata: bool, shareholders: &[Pubkey]) -> Instruction {
    let ck = v.coin();
    let (cv, cv_ata) = ck.creator_vault_for(&live_creator(v));
    let mut d = IX_PUMP_DISTRIBUTE_V2.to_vec();
    d.push(u8::from(initialize_ata));
    let mut accounts = vec![
        AccountMeta::new(*payer, true),
        r(ck.mint),
        r(ck.curve),
        r(ck.sharing_config),
        w(cv),
        r(system()),
        r(pk(c::PUMP_EVENT_AUTHORITY)),
        r(pump()),
        w(cv_ata),
        r(ck.quote_mint),
        r(tokenkeg()),
        r(pk(c::ATA_PROGRAM_ID)),
    ];
    accounts.extend(shareholders.iter().map(|k| w(*k)));
    Instruction { program_id: pump(), accounts, data: d }
}

// ---------------------------------------------------------- pump math ----

/// Curve reserves `(vT, vQ, rT, complete)` from the live curve.
pub fn curve_reserves(v: &Vault) -> (u64, u64, u64, u8) {
    let d = v.data(&v.coin().curve);
    (u64_at(&d, 8), u64_at(&d, 16), u64_at(&d, 24), d[48])
}

/// PumpSwap effective reserves `(B, Q)` = (base TA, quote TA + vqr).
pub fn pool_reserves(v: &Vault) -> (u64, u64) {
    let ck = v.coin();
    let p = v.data(&ck.pool);
    let vqr = if p.len() >= 261 { i128::from_le_bytes(p[245..261].try_into().unwrap()) } else { 0 };
    let quote = u64::try_from(i128::from(v.token_amount(&ck.pool_quote_ta)) + vqr).unwrap();
    (v.token_amount(&ck.pool_base_ta), quote)
}
