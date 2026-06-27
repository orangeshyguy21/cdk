#!/usr/bin/env bash
# Bell-curve outstanding visualizer for keyset rotation. Runs forever (Ctrl-C).
#
# Each keyset's outstanding traces a bell that spans TWO rotation windows:
#   • Rising half: the window during which the keyset is active. We migrate
#     proofs from the previous keyset into this one along sin²(π/2 · τ/W).
#   • Falling half: the next window (this keyset is now the previous one).
#     Migration into the new active keyset drains this one along cos²(π/2 · τ/W).
# The bell peaks AT the rotation moment, when migration into this keyset just
# completed and migration out is about to begin. Adjacent bells overlap during
# their shared window — they cross at 50% in the middle.
#
# Mechanics: on each tick within a window, compute target migrated amount
#   target(τ) = WINDOW_BALANCE · sin²(π/2 · τ/W)
# and send a swap of (target − already_migrated) sats. The send picks proofs
# (biased toward the older, plentiful keyset by coin-selection), the receive
# re-issues them in the active keyset. Smooth curve, no cliffs.
#
# Must match the mint's `[autorotate].rotation_by_time_seconds`.
#
# Overrides: MINT_URL, SEED_AMOUNT, REFILL_FACTOR,
#            ROTATION_PERIOD_SECONDS, TICK_SECONDS, MIN_MIGRATE_SAT

set -u

MINT_URL=${MINT_URL:-http://127.0.0.1:8089}
SEED_AMOUNT=${SEED_AMOUNT:-50000}
REFILL_FACTOR=${REFILL_FACTOR:-4}            # refill when balance < SEED_AMOUNT / factor
ROTATION_PERIOD_SECONDS=${ROTATION_PERIOD_SECONDS:-60}
TICK_SECONDS=${TICK_SECONDS:-0.5}            # migration granularity (smaller = smoother curve)
MIN_MIGRATE_SAT=${MIN_MIGRATE_SAT:-32}       # skip swaps smaller than this

CDK=${CDK:-./target/release/cdk-cli}

[[ -x "$CDK" ]] || { echo "cdk-cli not found at $CDK" >&2; exit 1; }

log() { printf '[swap-pretty %s] %s\n' "$(date +%H:%M:%S)" "$*"; }

balance() {
  $CDK balance 2>/dev/null \
    | awk -v u="$MINT_URL" '$0 ~ u { for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) { print $i; exit } }'
}

active_keyset() {
  curl -s --max-time 2 "$MINT_URL/v1/keysets" 2>/dev/null \
    | python3 -c "import json,sys
try:
    ks=json.load(sys.stdin).get('keysets',[])
    for k in ks:
        if k.get('active') and k.get('unit')=='sat':
            print(k['id']); break
except Exception:
    pass" 2>/dev/null
}

migrate() {
  local amt=$1 token
  (( amt < MIN_MIGRATE_SAT )) && return
  token=$($CDK send --mint-url "$MINT_URL" --amount "$amt" 2>/dev/null \
          | grep -oE 'cashu[ABCD][A-Za-z0-9_=-]+' | head -1)
  [[ -n "$token" ]] && $CDK receive "$token" >/dev/null 2>&1 || true
}

trap 'exit 0' INT TERM

log "initial mint $SEED_AMOUNT sat"
$CDK mint "$MINT_URL" "$SEED_AMOUNT" >/dev/null 2>&1 || true

LAST_KEYSET=""
ROTATION_TIME=0
WINDOW_BALANCE=0
MIGRATED=0

while :; do
  NOW=$(date +%s)
  BAL=$(balance)

  if [[ -z "$BAL" || "$BAL" -lt $((SEED_AMOUNT / REFILL_FACTOR)) ]]; then
    log "refill mint $SEED_AMOUNT sat (balance ${BAL:-0})"
    $CDK mint "$MINT_URL" "$SEED_AMOUNT" >/dev/null 2>&1 || true
    BAL=$(balance)
    WINDOW_BALANCE=${BAL:-$SEED_AMOUNT}
    MIGRATED=0
    ROTATION_TIME=$NOW
    sleep "$TICK_SECONDS"
    continue
  fi

  CUR_KEYSET=$(active_keyset)

  # Rotation (or initial detection) — reset the migration target for the new window.
  if [[ -n "$CUR_KEYSET" ]]; then
    if [[ -z "$LAST_KEYSET" ]]; then
      LAST_KEYSET="$CUR_KEYSET"
      ROTATION_TIME=$NOW
      WINDOW_BALANCE=$BAL
      MIGRATED=0
      log "initial keyset ${CUR_KEYSET:0:12}…  balance $BAL"
    elif [[ "$CUR_KEYSET" != "$LAST_KEYSET" ]]; then
      log "rotation ${LAST_KEYSET:0:12}… → ${CUR_KEYSET:0:12}…  balance $BAL"
      LAST_KEYSET="$CUR_KEYSET"
      ROTATION_TIME=$NOW
      WINDOW_BALANCE=$BAL
      MIGRATED=0
    fi
  fi

  ELAPSED=$(( NOW - ROTATION_TIME ))

  # target(τ) = WINDOW_BALANCE · sin²(π/2 · phase), capped at WINDOW_BALANCE.
  # Diff is what we still need to migrate to stay on the curve this tick.
  DIFF=$(awk \
    -v elapsed="$ELAPSED" \
    -v window="$ROTATION_PERIOD_SECONDS" \
    -v bal="$WINDOW_BALANCE" \
    -v migrated="$MIGRATED" \
    'BEGIN {
      pi = 3.14159265358979
      phase = elapsed / window
      if (phase > 1) phase = 1
      s = sin((pi/2) * phase)
      target = int(bal * s * s)
      d = target - migrated
      if (d < 0) d = 0
      print d
    }')

  if (( DIFF >= MIN_MIGRATE_SAT )); then
    migrate "$DIFF"
    MIGRATED=$((MIGRATED + DIFF))
  fi

  sleep "$TICK_SECONDS"
done
