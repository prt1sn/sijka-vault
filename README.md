# Sijka Vault

Source code of `sijka-vault`, the Solana program that holds the SIJKA treasury. It is published so that anyone
can check that the program deployed on mainnet is built from exactly this code.

## Addresses (mainnet)

| what | address |
|---|---|
| Program | `CBcQHhWwfAHHAv2U4Zj84uyYjSJUTvx9HFeARfCTWMa6` |
| Vault state (`config` PDA, seeds `["config"]`) | `CXBZSMLHAfyBMKyhmXD2srWZo8CaG6NrovfkhHeG367d` |
| Fee inbox (`fee_inbox` PDA, seeds `["fee_inbox"]`), the only pump.fun fee-sharing recipient | `4zUKnccJJatvYUf2vAPtUx2PUNdoB2qKA5w3v5Sx3RpK` |
| The vault's Phoenix Perpetuals trading account | `2VQrcwLYpc8TaXoEXeaS92mcD7S6kUBWvaN6BbPKUDjS` |
| SIJKA token mint | `4RQTS2Q6B32PZNLGmpwLUm3W6pYF2DgkyYAQzdYdpump` |
| pump.fun fee-sharing config of the token | `2ovWR1vpj4bbuuCKoZAn3cjnfPKLFAauRChZXxQkSjmE` |
| Admin set at initialization, fixed forever (also the emergency recovery recipient, see below) | `7TqMhwFSCMmfyTNQdgpW882sqjk4eUbDKPYLbRwowrgC` |
| Receiver of the 20% profit share (`creator_payout`, fixed forever) | `7TqMhwFSCMmfyTNQdgpW882sqjk4eUbDKPYLbRwowrgC` |

- Release: `v1.0.1`, executable hash `f751cbc240d862ca612a81e80647cf2ba656a2ba61e301202a0a981880f9749e`
- Project: https://sijka.xyz
- Security policy: [SECURITY.md](SECURITY.md)

Whether the program can still be upgraded is shown on any explorer (`Upgradeable: Yes/No`) and by
`solana program show CBcQHhWwfAHHAv2U4Zj84uyYjSJUTvx9HFeARfCTWMa6` (`Authority: none` once it is frozen). The admin, the current trading key, the
current keeper key and the parameters (fixed at initialization) are fields of the `config` account.

## v1.0.1: PumpSwap reserve compatibility

PumpSwap can retain fees in its quote vault and represent the adjustment with a negative
`virtual_quote_reserves`. The previous release rejected any negative value, which could block the
transition to PumpSwap and subsequent buybacks after migration. This release computes effective quote
liquidity as `quote_vault_balance + signed virtual_quote_reserves`, using checked arithmetic and requiring
the result to remain in `0..2^63−1`. The same effective liquidity drives observations and buyback limits;
fees do not have to be swept before each buyback. Pool bindings, coin checks, buyback limits, burn behavior,
the profit split and authorities are unchanged. This upgrade does not freeze the program.

See [Pump's signed reserve documentation](https://github.com/pump-fun/pump-public-docs/blob/8cda1fa30ea658b20909d8aedf002047119388d2/docs/NEGATIVE_VIRTUAL_QUOTE_RESERVES.md)
for the upstream change and pricing formula.

## In short

- **Money in.** The vault is funded by the pump.fun creator fee of SIJKA. Anything anyone sends to its addresses, the
  developer included, also becomes capital. Capital is never paid out as profit.
- **Trading.** The developer trades the vault's single Phoenix Perpetuals account through this program, with no limits
  on markets, size or leverage. Trading can lose money. No instruction of this program lets anyone, including the
  developer and the admin, withdraw the capital. Until the program is frozen, its upgrade authority could replace it
  (see **One wallet** and the upgrade status above).
- **Profit.** Only realized profit above everything ever deposited is paid: 80% buys SIJKA and burns it, 20% goes to
  the developer's wallet (`creator_payout`). The first payout is allowed right after launch; after that, at most once
  every 7 days, and only when at least 25 USDC is payable.
- **Admin.** After setup the admin wallet can do exactly two things: replace (or switch off) the trading key and the
  keeper key. There are no pauses and no adjustable parameters; the admin can neither give up its role nor hand it
  over.
- **Keeper key.** Only the keeper key can swap the collected fees (SOL to USDC, and USDC to SOL for the buyback) and
  buy SIJKA for the burn, each time with a minimum output it sets itself; the program has no price oracle and bounds
  only the size and frequency of these trades.
- **Emergency.** If Phoenix stops working for 10 days in a row by its own on-chain data (including when Phoenix
  changes the format of its data so that this program no longer recognizes it), the capital goes to the admin wallet.
  This is the only way capital can leave the vault other than the buyback and the 20% share.
- **One wallet.** At launch the admin wallet is also the upgrade authority (until the program is frozen), the pump.fun
  creator of SIJKA and the `creator_payout` wallet: the admin and profit-share addresses above are the same. Whoever
  holds it controls all of these roles (see Compromised keys below).

## What the program does

1. **Fees in.** The pump.fun creator fee of SIJKA is shared, once and forever, 100% to the `fee_inbox` PDA. The
   keeper key (see [Roles](#roles)) swaps SOL fees to USDC through Jupiter: it passes a minimum output (its quote
   minus its slippage) that the program enforces; the program has no oracle. A permissionless instruction deposits
   the USDC into the vault's single Phoenix Perpetuals account, whose authority is a PDA of this program. There is
   no deposit instruction for people: whatever reaches the vault, fees or donations, is counted as capital, never
   as profit.
2. **Trading.** The developer trades the vault through the program's API: a single pass-through instruction,
   `trade`, signed by the trading key (see [Trading](#trading-pass-through-of-phoenix-trading-instructions)).
3. **Profit.** A permissionless `harvest` withdraws realized profit above the high-water mark. The first harvest is
   allowed right after `initialize`; every later one at most once per `T_min` (7 days at launch) after the previous
   one. 80% buys back and burns SIJKA, 20% goes to the fixed `creator_payout` wallet.
4. **Buyback and burn.** The keeper key buys SIJKA on pump.fun (bonding curve, or PumpSwap after migration) in
   small chunks bounded by the program (chunk size as a share of an averaged pool reserve and an absolute cap, a
   volume limit per interval, top-level only, Jito `jitodontfront`, pinned accounts) with its own minimum output as
   the price limit; everything bought is burned in the same instruction. Observations and burning donations are
   permissionless.
5. **Venue watch.** A permissionless instruction records on chain whether Phoenix is working. It drives the
   emergency recovery below.

## Trust model

### No withdrawals

No instruction sends the vault's capital to a wallet, and no instruction takes a destination address as an
argument: every destination is fixed at initialization. Money leaves the vault in exactly three ways:

1. **Buyback and burn:** 80% of realized profit above the high-water mark.
2. **Profit share:** 20% of the same profit, to `creator_payout` (fixed at initialization, cannot be changed).
3. **Emergency recovery:** the single exception, only if Phoenix itself stops working (see below).

Apart from these, the vault's value changes only through the market: trading profit and loss, Phoenix, Ember and
pump.fun fees (the program pays whatever they charge), funding, swap and buyback prices within the program's
bounds, and rent. Nobody, including the admin, the trading key, the keeper key and the developer, has a withdrawal
path.

### Trading: pass-through of Phoenix trading instructions

The vault's Phoenix account is `(PDA, 0, 0)`: both its authority and its position authority are PDAs of this
program, and no delegate is ever set. The trading key signs `trade`; the program forwards one Phoenix instruction
as given and signs it with its PDA. Before forwarding, the program checks only that:

- the instruction is signed by the current trading key;
- the target program is Phoenix;
- the Phoenix instruction is on a fixed allowlist of **trading** instructions: orders of all kinds (limit,
  post-only, immediate-or-cancel / market, multi-order batches), cancels, stop-loss and conditional orders;
- the trader account is the vault's own account `(PDA, 0, 0)`;
- none of the program's PDA accounts is passed in any other account slot.

Everything else is rejected: withdrawals, deposits, collateral transfers, native swaps, sub-account and parent
sync, delegation, trader registration, proxy and permission instructions. A new Phoenix trading instruction can be
added only by a program upgrade, and only while the program is upgradeable.

There are **no** limits on markets, size, leverage or price, and no trading pause: the trading key trades freely,
and trading can lose money. What the program cannot prevent is bad trading, including trades against another
account at unfavourable prices. The trading key still cannot withdraw anything.

### Profit and the high-water mark

Amounts are USDC atoms (10^-6 USDC). `I` is everything ever deposited into Phoenix (only deposits increase it).
`O` is profit already paid out (only `harvest` increases it). `C`, `U` and `F` are the account's settled USDC
collateral, unrealized PnL and unsettled funding, read on chain from Phoenix's margin view.

```
payable = C − I + min(0, U + F)
```

`C` already excludes earlier payouts, so the high-water mark is exactly `O`: only realized profit above everything
paid before is payable, positive unrealized PnL is never paid, and losses must be earned back first. `harvest` also
keeps a margin buffer and requires a minimum payout (25 USDC at launch) and, after the first payout, the interval
`T_min` (7 days at launch); `initialize` sets `last_harvest_ts = created_ts - t_min_secs`, so the first harvest
needs no wait. Each payout is split `floor(payout × 20%)` to `creator_payout`, the rest to buyback and burn.

One case the program cannot tell apart: USDC that someone transfers from their own Phoenix account directly into
the vault's account bypasses the deposit and is paid out as profit (80% burned, 20% profit share).

### Emergency recovery (the only exception)

If Phoenix is **not working for 10 consecutive days according to its own on-chain data**, anyone can switch the
vault into an irreversible recovery mode, and the vault's capital, including profit not yet harvested, goes to the
admin wallet fixed at initialization. The reason: the capital is creator fees; holders did not deposit it.

- "Not working" means: the Phoenix exchange is not active (inactive, maintenance or suspended status), or none of
  the SOL, BTC and ETH perpetual markets is active on Phoenix (the three are constants in the program, looked up by
  symbol rather than by account address), or the Phoenix global config account or the Phoenix program itself is
  gone, or Phoenix has changed the format of its global config or market map so that the program no longer
  recognizes it (owner, length, discriminator, anchors, status bits, entry layout, counters). The last case is an
  accepted risk: a Phoenix upgrade that changes these formats and is not followed by an upgrade of this program
  starts the count. Transient anomalies (an inconsistent restart record, a duplicated, renamed or missing SOL, BTC
  or ETH entry) count as "unknown" and reset the count.
- A permissionless observe instruction keeps the count: the first "not working" observation starts it, any
  "working" or "unknown" observation resets it to zero, and a gap of more than one hour between "not working"
  observations starts it over. The trigger checks the live status again. The admin cannot influence the verdict.
- After the trigger, deposits and harvests stop, and the trading key's remaining role is to close positions.
  Collateral is withdrawn from Phoenix as far as Phoenix allows and forwarded to the recipient.
- Money already assigned to the buyback (the 80%) is still burned, and the 20% already assigned is still paid.
- The recipient is always the admin wallet recorded at initialization; the admin cannot be renounced or changed.
- Nobody, including the admin, can trigger the recovery early, delay it or change the recipient.

### Roles

| role | set by | can | cannot |
|---|---|---|---|
| admin | initialization; exists forever, never changes | replace or switch off the trading key and the keeper key, effective at once; one-time setup (token mint, Phoenix registration) | withdraw; change any parameter (all are fixed at initialization); pause anything; change `creator_payout`; change the admin; trigger, delay or redirect the emergency recovery |
| trading key | the admin | `trade` only | withdraw or move collateral; touch funds outside Phoenix; act on any other account |
| keeper key | the admin | the fee swaps (SOL→USDC, USDC→SOL for the buyback) and the buyback chunks, each with its own minimum output, within the program's size and interval limits | withdraw; send the output anywhere but the vault's own accounts; exceed the chunk and swap limits |
| `creator_payout` | initialization, fixed | receives the 20% share | anything in the program |
| anyone | none | every other crank: deposit, harvest, profit-share payout, buyback observations, burn of donations, venue watch, recovery steps | send funds anywhere except the fixed destinations |
| upgrade authority | deployment | replace the program until the upgrade authority is set to none | nothing once frozen |

There are no pauses and no adjustable parameters: payout, swap and buyback parameters are fixed at initialization.

### Compromised keys (accepted risks)

- **Trading key:** can lose the vault's value by trading, including trades against another account at bad prices;
  cannot withdraw. The admin replaces it at once.
- **Keeper key:** can swap the fees not yet swapped and the buyback USDC through a bad route and buy chunks at a bad
  price, within the program's per-call limits (and interval limits where the parameters set them; the fee swap
  interval `swap_min_interval_s` may be 0), until the admin replaces it; cannot withdraw.
- **Admin:** can appoint its own trading key and trade badly, or its own keeper key and swap or buy at bad prices
  within the limits. Its wallet is the emergency recovery recipient and, at launch, also the `creator_payout` wallet
  and the upgrade authority: whoever holds it gets the 20% share not yet paid out and, until the freeze, can replace
  the program. It has no other way to withdraw.
- **Upgrade authority:** can replace the program until it is frozen. Check the upgrade status first; the rest of
  this section assumes the deployed code is the code in this repository.

### External dependencies

- **Phoenix Perpetuals** (with its Hawkeye margin view and the Ember USDC wrapper): closed source, upgradeable by
  its own multisig; it can freeze accounts or change its interface. The emergency recovery relies on its on-chain
  status.
- **Jupiter** routes the fee swaps; the program checks the result against the keeper's minimum output, the exact
  spent amount and the state of its own swap accounts, but not against an oracle price.
- **pump.fun** administrators have powers over fee-sharing configs, token creator settings and fees.

## Verify the deployed program

You need Linux on x86_64 (or any host that runs `linux/amd64` Docker images) and Docker. Builds on Windows do not
reproduce the hash.

```sh
cargo install solana-verify --version 0.5.2 --locked
git clone https://github.com/prt1sn/sijka-vault sijka-vault
cd sijka-vault
git checkout v1.0.1
solana-verify build --arch v3 --library-name sijka_vault
solana-verify get-executable-hash target/deploy/sijka_vault.so
solana-verify get-program-hash -u mainnet-beta CBcQHhWwfAHHAv2U4Zj84uyYjSJUTvx9HFeARfCTWMa6
```

The last two hashes must be equal, and for release `v1.0.1` both equal `f751cbc240d862ca612a81e80647cf2ba656a2ba61e301202a0a981880f9749e`.
`solana-verify build` compiles inside the `solanafoundation/solana-verifiable-build` Docker image, pinned by digest
and selected by the Solana version in `[workspace.metadata.cli]` of `Cargo.toml`; `Cargo.lock` pins every
dependency. The program is built as SBPFv3 (`--arch v3`, ELF `e_flags` 3); without the flag the hash differs.

Also:

- `https://verify.osec.io/status/CBcQHhWwfAHHAv2U4Zj84uyYjSJUTvx9HFeARfCTWMa6` returns the verification record (repository, commit, hashes);
  explorers show it as "Verified Build".
- The program embeds a `security.txt` (name, project URL, contacts, policy, source code, release, auditors).
  Explorers show it, and `query-security-txt target/deploy/sijka_vault.so` prints it from a local build.
- A plain `cargo build-sbf` is fine for development but is not guaranteed to produce the same hash.

## Build and test

```sh
cargo test --locked -p sijka-vault
cargo build-sbf --arch v3 --manifest-path programs/sijka-vault/Cargo.toml -- --locked
```

The host unit tests run anywhere. The LiteSVM integration tests in `programs/sijka-vault/tests` need Linux and
mainnet program binaries and account snapshots (see the fetch scripts in `programs/sijka-vault/tests/fixtures`);
without them they may be skipped.

## Copyright

Copyright (c) 2026 prt1sn. All rights reserved. The source is published for reading and
build verification only; see [COPYRIGHT](COPYRIGHT). No license to use, reproduce or deploy it is granted.
