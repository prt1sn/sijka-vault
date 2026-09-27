#!/usr/bin/env node
// owner: tests/buyback
//
// Fetch the mainnet fixtures of the buyback LiteSVM tests (tests/buyback):
// the real pump / pump_amm / pump_fees / Token-2022 / SPL Token / ATA
// binaries and a snapshot of every account the tests load (pump Global and
// fee configs, fee recipients and their quote ATAs, the coins of coins.json
// with their curve / pool accounts, the USDC and wSOL mints, the Phoenix
// GlobalConfig, Ember state and PerpAssetMap read by `initialize` and tag 43).
//
//   node programs/sijka-vault/tests/fixtures/buyback/fetch.mjs <out_dir>
//
// Plain Node >= 18 (global fetch, node:crypto), no npm packages. PDAs and
// ATAs are derived here (ed25519 on-curve check included), so fee recipients
// are always the ones pump's Global / GlobalConfig list today. Public data
// only; no key or secret is read or written. RPC: $SOLANA_RPC_URL, default
// the public mainnet-beta endpoint (429s are retried).

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = process.argv[2] || join(HERE, "../../../../../target/deploy/.cache/buyback");
const RPC = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";

// ---------------------------------------------------------------- base58

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let s = "";
  while (n > 0n) {
    s = ALPHABET[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s;
}
function b58decode(str) {
  let n = 0n;
  for (const c of str) {
    const i = ALPHABET.indexOf(c);
    if (i < 0) throw new Error("bad base58: " + str);
    n = n * 58n + BigInt(i);
  }
  const out = [];
  while (n > 0n) {
    out.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const c of str) {
    if (c !== "1") break;
    out.unshift(0);
  }
  return Uint8Array.from(out);
}
const key = (s) => {
  const b = b58decode(s);
  if (b.length !== 32) throw new Error("not a 32-byte key: " + s);
  return b;
};

// --------------------------------------------------- ed25519 on-curve check

const P = 2n ** 255n - 19n;
const D = (-121665n * modInv(121666n)) % P;
const SQRT_M1 = modPow(2n, (P - 1n) / 4n, P);
function mod(a) {
  const r = a % P;
  return r >= 0n ? r : r + P;
}
function modPow(b, e, m) {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}
function modInv(a) {
  return modPow(mod(a), P - 2n, P);
}
/** Whether 32 bytes decode to a point on ed25519 (as `is_on_curve`). */
function isOnCurve(bytes) {
  const b = Uint8Array.from(bytes);
  b[31] &= 0x7f;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(b[i]);
  if (y >= P) return false;
  const y2 = mod(y * y);
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  const v3 = mod(v * v * v);
  const v7 = mod(v3 * v3 * v);
  let x = mod(u * v3 * modPow(mod(u * v7), (P - 5n) / 8n, P));
  const vx2 = mod(v * x * x);
  if (vx2 === u) return true;
  if (vx2 === mod(-u)) return true;
  return false;
}

// ------------------------------------------------------------------- PDAs

function createProgramAddress(seeds, programId) {
  const h = createHash("sha256");
  for (const s of seeds) h.update(s);
  h.update(programId);
  h.update(Buffer.from("ProgramDerivedAddress"));
  const out = h.digest();
  return isOnCurve(out) ? null : Uint8Array.from(out);
}
function pda(seeds, programId) {
  for (let bump = 255; bump >= 0; bump--) {
    const k = createProgramAddress([...seeds, Uint8Array.of(bump)], programId);
    if (k) return k;
  }
  throw new Error("no PDA");
}
const s = (str) => Buffer.from(str);

const PUMP = key("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P");
const AMM = key("pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA");
const FEES = key("pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ");
const TOKENKEG = key("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const T22 = key("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const ATA_PROGRAM = key("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const WSOL = key("So11111111111111111111111111111111111111112");
const USDC = key("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const ata = (owner, tp, mint) => pda([owner, tp, mint], ATA_PROGRAM);

// Self-check of the derivation against constants of the program (SPEC §2.3).
if (b58encode(pda([s("global")], PUMP)) !== "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf") {
  throw new Error("PDA derivation self-check failed");
}
if (b58encode(pda([s("fee_config"), AMM], FEES)) !== "5PHirr8joyTMp9JMm6nW7hNDVyEYdkzDqazxPD7RaTjx") {
  throw new Error("PDA derivation self-check failed (fee_config)");
}

// -------------------------------------------------------------------- RPC

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function rpc(method, params) {
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(RPC, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      if (res.status === 429 || res.status >= 500) throw new Error("HTTP " + res.status);
      const j = await res.json();
      if (j.error) throw new Error(JSON.stringify(j.error));
      return j.result;
    } catch (e) {
      if (attempt >= 12) throw e;
      await sleep(Math.min(30000, 1000 * 2 ** attempt));
    }
  }
}
async function getMany(keys) {
  const out = [];
  let slot = 0;
  for (let i = 0; i < keys.length; i += 50) {
    const batch = keys.slice(i, i + 50);
    const r = await rpc("getMultipleAccounts", [batch, { encoding: "base64", commitment: "confirmed" }]);
    slot = Math.max(slot, r.context.slot);
    out.push(...r.value);
    await sleep(250);
  }
  return { slot, value: out };
}

// ------------------------------------------------------------ programs

const PROGRAMS = [
  ["pump", "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"],
  ["pump_amm", "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"],
  ["pump_fees", "pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ"],
  ["token_2022", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"],
  ["spl_token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
  ["associated_token", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"],
];
const UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111";

async function dumpProgram(name, id) {
  const file = join(OUT, "programs", name + ".so");
  if (existsSync(file) && statSync(file).size > 0) return;
  const r = await rpc("getAccountInfo", [id, { encoding: "base64", commitment: "confirmed" }]);
  if (!r.value) throw new Error("program missing: " + id);
  let data = Buffer.from(r.value.data[0], "base64");
  if (r.value.owner === UPGRADEABLE) {
    const pd = b58encode(data.subarray(4, 36));
    const r2 = await rpc("getAccountInfo", [pd, { encoding: "base64", commitment: "confirmed" }]);
    data = Buffer.from(r2.value.data[0], "base64").subarray(45);
  }
  if (data.subarray(0, 4).toString("latin1") !== "\x7fELF") throw new Error("not an ELF: " + name);
  // ProgramData is allocated with `--max-len`: drop the zero padding after the
  // ELF (end = the furthest of the section header table and every section).
  const shoff = Number(data.readBigUInt64LE(0x28));
  const shentsize = data.readUInt16LE(0x3a);
  const shnum = data.readUInt16LE(0x3c);
  let end = shoff + shentsize * shnum;
  for (let i = 0; i < shnum; i++) {
    const h = shoff + i * shentsize;
    const type = data.readUInt32LE(h + 4);
    const off = Number(data.readBigUInt64LE(h + 0x18));
    const size = Number(data.readBigUInt64LE(h + 0x20));
    if (type !== 8 /* SHT_NOBITS */) end = Math.max(end, off + size);
  }
  if (end > 0 && end <= data.length) data = data.subarray(0, end);
  writeFileSync(file, data);
  console.log(`program ${name} ${id}: ${data.length} bytes`);
}

// ------------------------------------------------------------ accounts

async function main() {
  mkdirSync(join(OUT, "programs"), { recursive: true });
  for (const [n, id] of PROGRAMS) await dumpProgram(n, id);
  if (existsSync(join(OUT, "accounts.json")) && !process.env.BB_FIXTURES_REFRESH) {
    console.log("accounts.json present (cache); set BB_FIXTURES_REFRESH=1 to refetch");
    return;
  }

  const list = [];
  const add = (k, label) => {
    const b = typeof k === "string" ? k : b58encode(k);
    if (!list.find((x) => x[0] === b)) list.push([b, label]);
  };
  const GLOBAL = "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf";
  const AMM_GC = "ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw";
  const PHX_GC = "2zskx2iyCvb6Stg7RBZkt1f6MrF4dpYtMG3yMvKwqtUZ";
  add(GLOBAL, "pump global");
  add(pda([s("fee_config"), PUMP], FEES), "pump fee_config");
  add(pda([s("global_volume_accumulator")], PUMP), "pump global_volume_accumulator");
  add(pda([s("__event_authority")], PUMP), "pump event_authority");
  add(AMM_GC, "amm global_config");
  add(pda([s("fee_config"), AMM], FEES), "amm fee_config");
  add(pda([s("global_volume_accumulator")], AMM), "amm global_volume_accumulator");
  add(pda([s("__event_authority")], AMM), "amm event_authority");
  add(pda([s("__event_authority")], FEES), "pump_fees event_authority");
  add(WSOL, "wsol mint");
  add(USDC, "usdc mint");
  add(PHX_GC, "phoenix global_config");
  add("6ur7v6AXNpnHeEb6xuk7PyezvZ1i5GrgYyWZkNCpzbRz", "ember state");
  // Mainnet rent (lamports_per_byte_year 5080, threshold 1.0 since 2026):
  // live accounts are rent-exempt only under it (pump_amm checks
  // `rent_exempt` on the coin creator vault ATA).
  add("SysvarRent111111111111111111111111111111111", "sysvar rent");

  const first = await getMany([GLOBAL, AMM_GC, PHX_GC]);
  const [g, gc, phx] = first.value.map((a) => Buffer.from(a.data[0], "base64"));
  add(phx.subarray(360, 392), "phoenix perp_asset_map");
  const at = (d, o) => d.subarray(o, o + 32);
  const recips = [[at(g, 41), "pump fee_recipient"], [at(g, 113), "pump withdraw_authority"]];
  for (let i = 0; i < 7; i++) recips.push([at(g, 162 + 32 * i), `pump fee_recipients[${i}]`]);
  for (let i = 0; i < 8; i++) recips.push([at(g, 741 + 32 * i), `pump buyback_fee_recipients[${i}]`]);
  for (let i = 0; i < 8; i++) recips.push([at(gc, 57 + 32 * i), `amm protocol_fee_recipients[${i}]`]);
  for (let i = 0; i < 8; i++) recips.push([at(gc, 643 + 32 * i), `amm buyback_fee_recipients[${i}]`]);
  for (const [k, l] of recips) {
    add(k, l);
    add(ata(k, TOKENKEG, WSOL), l + " wsol ata");
    add(ata(k, TOKENKEG, USDC), l + " usdc ata");
  }

  const coins = JSON.parse(readFileSync(join(HERE, "coins.json"), "utf8")).coins;
  const mints = await getMany(coins.map((c) => c.mint));
  coins.forEach((c, i) => {
    const mi = mints.value[i];
    if (!mi) throw new Error("coin mint missing: " + c.mint);
    const M = key(c.mint);
    const Q = c.quote === "usdc" ? USDC : WSOL;
    const TP = key(mi.owner);
    const L = c.label;
    add(M, L + " mint");
    const curve = pda([s("bonding-curve"), M], PUMP);
    add(curve, L + " bonding_curve");
    add(ata(curve, TP, M), L + " curve base ata");
    add(ata(curve, TOKENKEG, Q), L + " curve quote ata");
    add(pda([s("bonding-curve-v2"), M], PUMP), L + " bonding_curve_v2");
    const sc = pda([s("sharing-config"), M], FEES);
    add(sc, L + " sharing_config");
    const cv = pda([s("creator-vault"), sc], PUMP);
    add(cv, L + " creator_vault");
    add(ata(cv, TOKENKEG, Q), L + " creator_vault quote ata");
    const pa = pda([s("pool-authority"), M], PUMP);
    add(pa, L + " pool_authority");
    const pool = pda([s("pool"), Uint8Array.of(0, 0), pa, M, Q], AMM);
    add(pool, L + " pool");
    add(ata(pool, TP, M), L + " pool base ta");
    add(ata(pool, TOKENKEG, Q), L + " pool quote ta");
    add(pda([s("pool-v2"), M], AMM), L + " pool_v2");
    const lp = pda([s("pool_lp_mint"), pool], AMM);
    add(lp, L + " lp_mint");
    add(ata(pa, T22, lp), L + " pool_authority lp ata");
    const ccva = pda([s("creator_vault"), sc], AMM);
    add(ccva, L + " coin_creator_vault_authority");
    add(ata(ccva, TOKENKEG, Q), L + " coin_creator_vault ata");
    add(ata(pa, TP, M), L + " pool_authority mint ata");
    add(ata(pa, TOKENKEG, Q), L + " pool_authority quote ata");
  });

  const r = await getMany(list.map((x) => x[0]));
  const accounts = [];
  const missing = [];
  r.value.forEach((a, i) => {
    const [pubkey, label] = list[i];
    if (!a) {
      missing.push({ pubkey, label });
      return;
    }
    accounts.push({
      pubkey,
      label,
      lamports: a.lamports,
      owner: a.owner,
      executable: a.executable,
      data: a.data[0],
    });
  });
  const doc = { slot: r.slot, fetched_at: new Date().toISOString(), rpc: RPC.replace(/\?.*$/, ""), accounts, missing };
  writeFileSync(join(OUT, "accounts.json"), JSON.stringify(doc));
  console.log(`accounts: ${accounts.length} present, ${missing.length} absent on mainnet, slot ${r.slot} -> ${OUT}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
