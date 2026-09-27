#!/usr/bin/env bash
# owner: tests/phoenix-core
#
# Dump the live mainnet accounts the phoenix-core LiteSVM tests read
# (tests/phoenix-core/token_mint.rs): a pump.fun Token-2022 mint and its
# pump_fees SharingConfig v2 (U-9, U-26). Read-only RPC (`solana account`),
# nothing is signed. Files are `<pubkey>.json` in the output directory and are
# reused when present (CI caches the directory for a day).
#
#   bash programs/sijka-vault/tests/fixtures/phoenix_core_fetch.sh <out-dir>
#
# Needs the Agave CLI (`solana`). RPC: $SIJKA_FIXTURE_RPC_URL or mainnet-beta.
set -euo pipefail

out="${1:?usage: phoenix_core_fetch.sh <out-dir>}"
rpc="${SIJKA_FIXTURE_RPC_URL:-https://api.mainnet-beta.solana.com}"
mkdir -p "$out"

accounts=(
  CpgnBP6XLaV6GKfiFYjvyhdA7pCpB1KQopqkz5dSpump # pump.fun coin mint (Token-2022)
  K2b5hhfphG9UQFtRgZbmd7q4LVDSP1R7Hmog2sNzk4w  # its SharingConfig (pump_fees)
)

for a in "${accounts[@]}"; do
  f="$out/$a.json"
  if [ -s "$f" ]; then
    echo "cached: $f"
    continue
  fi
  for attempt in 1 2 3 4 5; do
    if solana account "$a" --url "$rpc" --output json-compact > "$f.tmp" 2> "$f.err"; then
      mv "$f.tmp" "$f"
      echo "fetched: $a ($(wc -c < "$f") bytes of JSON)"
      break
    fi
    echo "attempt $attempt for $a failed: $(head -c 300 "$f.err")"
    rm -f "$f.tmp"
    sleep $((attempt * 5))
  done
  rm -f "$f.err"
  [ -s "$f" ] || { echo "::error::could not fetch $a"; exit 1; }
done
