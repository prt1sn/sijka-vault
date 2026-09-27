#!/usr/bin/env bash
# owner: tests/recovery
#
# Fetch the mainnet account snapshots used by the recovery LiteSVM tests
# (tests/recovery, SPEC §9.11 "копии живых GC и PAM"): raw account data of
#   - Phoenix GlobalConfig  2zskx2iyCvb6Stg7RBZkt1f6MrF4dpYtMG3yMvKwqtUZ
#   - Phoenix PerpAssetMap  (the key at GlobalConfig@360..392)
#   - the Phoenix program account and its ProgramData (step X1, O-14).
# Read-only RPC calls (`solana account`), nothing is signed. Files that are
# already present are kept (CI caches the directory for a day).
#
#   bash programs/sijka-vault/tests/fixtures/fetch-recovery-mainnet.sh [out_dir]
#
# out_dir defaults to $SIJKA_RECOVERY_MAINNET_DIR or target/recovery-mainnet;
# the RPC to $SIJKA_MAINNET_RPC_URL or the public mainnet-beta endpoint.
set -euo pipefail

out="${1:-${SIJKA_RECOVERY_MAINNET_DIR:-target/recovery-mainnet}}"
rpc="${SIJKA_MAINNET_RPC_URL:-https://api.mainnet-beta.solana.com}"
mkdir -p "$out"

GLOBAL_CONFIG=2zskx2iyCvb6Stg7RBZkt1f6MrF4dpYtMG3yMvKwqtUZ
PHOENIX=EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih
PHOENIX_PROGRAM_DATA=B5ayDaz9HegiNZqYeBtcFqfZBVSGwjB2CJgHshoSfMQg

fetch() {
  local addr=$1 file=$2
  if [ -s "$out/$file" ]; then
    echo "cached $file ($(stat -c %s "$out/$file") bytes)"
    return 0
  fi
  for attempt in 1 2 3 4 5; do
    if solana account -u "$rpc" "$addr" --output-file "$out/$file.tmp" >/dev/null 2>"$out/$file.err"; then
      mv "$out/$file.tmp" "$out/$file"
      echo "fetched $file: $addr ($(stat -c %s "$out/$file") bytes)"
      return 0
    fi
    echo "attempt $attempt for $addr failed: $(tail -1 "$out/$file.err")"
    sleep $((attempt * 5))
  done
  echo "::error::could not fetch $addr"
  return 1
}

fetch "$GLOBAL_CONFIG" global_config.bin
# PerpAssetMap key = GlobalConfig@360..392 (base58).
pam=$(python3 -c '
import sys
d = open(sys.argv[1], "rb").read()[360:392]
a = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n = int.from_bytes(d, "big")
s = ""
while n:
    n, r = divmod(n, 58)
    s = a[r] + s
print("1" * (len(d) - len(d.lstrip(b"\0"))) + s)
' "$out/global_config.bin")
echo "PerpAssetMap (GlobalConfig@360): $pam"
if [ -s "$out/perp_asset_map.key" ] && [ "$(cat "$out/perp_asset_map.key")" != "$pam" ]; then
  rm -f "$out/perp_asset_map.bin"
fi
echo "$pam" > "$out/perp_asset_map.key"
fetch "$pam" perp_asset_map.bin
fetch "$PHOENIX" phoenix_program.bin
fetch "$PHOENIX_PROGRAM_DATA" phoenix_program_data.bin
[ -s "$out/slot.txt" ] || solana slot -u "$rpc" > "$out/slot.txt" 2>/dev/null || echo unknown > "$out/slot.txt"
rm -f "$out"/*.err
ls -l "$out"
