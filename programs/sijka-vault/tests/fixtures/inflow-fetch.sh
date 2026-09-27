#!/usr/bin/env bash
# owner: tests/inflow
#
# Mainnet fixtures of the inflow LiteSVM tests (programs/sijka-vault/tests/inflow):
# - the Jupiter v6 program (JUP6…) and the SPL token-swap program (SwaPpA9…),
#   dumped with `solana program dump`;
# - one consistent snapshot (a single getMultipleAccounts call) of a live
#   SOL/USDC token-swap pool that Jupiter routes through, plus the USDC mint.
#
# Read-only RPC; nothing is signed. Output (default target/deploy/.cache-inflow,
# ignored by git) is cached by CI for a day. Usage:
#   bash programs/sijka-vault/tests/fixtures/inflow-fetch.sh [out_dir]
set -euo pipefail

out="${1:-target/deploy/.cache-inflow}"
rpc="${SIJKA_FIXTURE_RPC_URL:-https://api.mainnet-beta.solana.com}"
mkdir -p "$out"

dump() {
  local id="$1" file="$2"
  if [ ! -s "$out/$file" ]; then
    for attempt in 1 2 3; do
      solana program dump -u "$rpc" "$id" "$out/$file" && break
      echo "retry $attempt: solana program dump $id" >&2
      sleep 5
    done
  fi
  ls -l "$out/$file"
}

dump JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 jupiter_v6-mainnet.so
dump SwaPpA9LAaLfeLi3a68M4DjnLqgtticKg6CnyNwgAC8 spl_token_swap-mainnet.so

# Order matters: the tests read the accounts by position.
#   0 swap state, 1 token A vault (wSOL), 2 token B vault (USDC), 3 pool mint,
#   4 pool fee account, 5 USDC mint,
#   6 / 7 wSOL / USDC token accounts of Jupiter's program authority id 4
#   (PDA(["authority", 4], JUP6), used by shared_accounts_route*).
keys='["AmHUjHKfSFP34D4VgPsviFNjWrvTN761Yazvv2eKAsSz","3vnX3jx5EDeraXUBSLDZbDZM3zz9CE8jd9xAeTp9L8bo","34YKkqGeqGfv3EJDV79Ewga67rZUgQTNDRwYQGoxMDmi","BNbehZgqKVQpdMZiAULM3589B7juRdiBemfWS9awHCaw","Hykjqd4zjw44AGgGspBMdPsopv5F7j96becedqRohdEQ","EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","6zAcFYmxkaH25qWZW5ek4dk4SyQNpSza3ydSoUxjTudD","m3BrPbv2TFmZZTPpyB9NgsCXqGNujpXvzvGqj8ksars"]'
snap="$out/jupiter_snapshot.json"
if [ ! -s "$snap" ]; then
  body="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getMultipleAccounts\",\"params\":[$keys,{\"encoding\":\"base64\"}]}"
  for attempt in 1 2 3; do
    if curl -sSf -m 60 "$rpc" -H 'Content-Type: application/json' -d "$body" -o "$snap.tmp" \
       && grep -q '"value"' "$snap.tmp"; then
      mv "$snap.tmp" "$snap"
      break
    fi
    echo "retry $attempt: getMultipleAccounts" >&2
    sleep 5
  done
fi
ls -l "$snap"
echo "$keys" > "$out/jupiter_snapshot.keys.json"
