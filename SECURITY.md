# Security policy

## Reporting a vulnerability

Report privately to the maintainer on X: **https://x.com/prt1sn** (direct message). The same contact is in the
`contacts` field of the `security.txt` embedded in the program. If direct messages are closed, reply publicly to
ask for a private channel, without any details of the issue.

Do not open a public issue, pull request or discussion for a vulnerability.

Please include:

- the release or commit, and the program id (`CBcQHhWwfAHHAv2U4Zj84uyYjSJUTvx9HFeARfCTWMa6` on mainnet);
- the affected instruction(s) and accounts;
- the impact: what can be stolen, frozen or mispaid, by whom, and under which preconditions;
- a reproduction, preferably a LiteSVM test against this repository or a simulated transaction. Never send a
  transaction against the live vault.

English or Russian.

## Scope

In scope: the `sijka-vault` program in this repository, as deployed at `CBcQHhWwfAHHAv2U4Zj84uyYjSJUTvx9HFeARfCTWMa6`, in particular:

- any way to move the vault's capital other than the buyback and burn, the 20% profit share to the fixed
  `creator_payout` wallet, and the emergency recovery under its on-chain conditions;
- any way to get a non-trading Phoenix instruction through `trade`, to act on an account other than the vault's
  own Phoenix account, or to misuse a signature of the program's PDAs;
- profit accounting errors: capital paid out as profit, more than 20% of the profit above the high-water mark
  paid to `creator_payout`, a bypass of `T_min` (the first harvest is allowed right after `initialize` by design) or
  of the minimum payout;
- triggering the emergency recovery early, blocking it while its conditions hold, or redirecting it;
- swap and buyback limits (keeper-only signing, minimum output, chunk size, per-interval volume, account checks)
  that can be bypassed beyond their documented bounds, in particular by anyone other than the keeper key;
- a mismatch between this source and the deployed binary (verified build).

Out of scope:

- Phoenix (including Hawkeye and Ember), Jupiter, pump.fun, the SPL Token programs and the Solana runtime:
  report those to their maintainers. A report showing how their behaviour breaks this program is in scope;
- trading results: losses from trades made with the trading key are a documented, accepted risk, not a
  vulnerability;
- the accepted risks listed in [README.md](README.md): a compromised admin, trading key or keeper key (within the
  documented limits), the upgrade authority before the program is frozen, a Phoenix data-format change counted as
  "not working", fee changes of Phoenix, Ember and pump.fun, and the powers of pump.fun administrators;
- the web site, off-chain bots and RPC providers;
- denial of service through public RPC endpoints or spam, social engineering, and physical attacks.

## Disclosure

- We aim to acknowledge a report within 72 hours and to share an assessment within 7 days.
- Coordinated disclosure: please keep the details private until a fix is deployed or 90 days have passed,
  whichever comes first; we agree on the publication date with you.
- While the program is upgradeable, fixes ship as program upgrades. Once it is frozen it cannot be changed; the
  issue is then published together with you, with the available mitigations.
- With your permission, you are credited in the release notes of the fix.
- There is no formal bug bounty at this time; any reward is at the maintainer's discretion.
- We will not pursue good-faith research that follows this policy, does not touch the funds of the live vault or of
  other users, and does not disrupt the service.

## Supported versions

Only the release currently deployed at `CBcQHhWwfAHHAv2U4Zj84uyYjSJUTvx9HFeARfCTWMa6`; its tag is the `source_release` field of the embedded
`security.txt`.

## Auditors

`None`
