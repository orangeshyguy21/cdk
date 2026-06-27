#!/usr/bin/env bash
# Continuous swap simulator. Runs forever (Ctrl-C to stop).
#
# Mints SEED_AMOUNT, then loops send/receive of SWAP_AMOUNT. Re-mints whenever
# balance drops below SWAP_AMOUNT * REFILL_FACTOR. Silent by design — dashboard
# pulls state from the mint (/v1/filters, /v1/keysets) and wallet sqlite.
#
# Overrides: MINT_URL, SEED_AMOUNT, SWAP_AMOUNT, REFILL_FACTOR, SLEEP_MS

set -u

MINT_URL=${MINT_URL:-http://127.0.0.1:8089}
SEED_AMOUNT=${SEED_AMOUNT:-50000}
SWAP_AMOUNT=${SWAP_AMOUNT:-32}
REFILL_FACTOR=${REFILL_FACTOR:-4}     # remint when balance < SWAP_AMOUNT * factor
SLEEP_MS=${SLEEP_MS:-0}               # optional throttle between iterations

CDK=${CDK:-./target/release/cdk-cli}

[[ -x "$CDK" ]] || { echo "cdk-cli not found at $CDK" >&2; exit 1; }

balance() {
  $CDK balance 2>/dev/null \
    | awk -v u="$MINT_URL" '$0 ~ u { for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) { print $i; exit } }'
}

trap 'exit 0' INT TERM

# Initial seed
$CDK mint "$MINT_URL" "$SEED_AMOUNT" >/dev/null 2>&1 || true

while :; do
  BAL=$(balance)
  if [[ -z "$BAL" || "$BAL" -lt $((SWAP_AMOUNT * REFILL_FACTOR)) ]]; then
    $CDK mint "$MINT_URL" "$SEED_AMOUNT" >/dev/null 2>&1 || true
  fi

  TOKEN=$($CDK send --mint-url "$MINT_URL" --amount "$SWAP_AMOUNT" 2>/dev/null \
          | grep -oE 'cashu[ABCD][A-Za-z0-9_=-]+' | head -1)

  if [[ -n "$TOKEN" ]]; then
    $CDK receive "$TOKEN" >/dev/null 2>&1 || true
  fi

  if (( SLEEP_MS > 0 )); then
    sleep "$(awk -v ms="$SLEEP_MS" 'BEGIN { print ms/1000 }')"
  fi
done
