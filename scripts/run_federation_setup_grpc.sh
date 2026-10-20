#!/usr/bin/env bash
# End-to-end federation setup driven only through the management gRPC.
#
# Every member starts as a fresh `cdk-mintd` in federation setup mode. The
# creator, the joiners, proposal approval, key generation, and activation are all
# driven with `cdk-mint-cli federation-setup`. After activation each daemon must
# come back, in the same process, as a running federation member on the same RPC
# port, and the federation must pass the paid mint/swap/melt smoke scenario.
#
# TRANSPORT=http (default) runs federation traffic over local HTTP. TRANSPORT=iroh
# makes every member Iroh-only for enrollment, key generation, and consensus;
# the management gRPC stays on localhost TCP either way.
#
# Operators in a GUI click in any order, so two switches change the order:
# APPROVE_ORDER=creator-last approves members 2..N before the creator
# (default creator-first), and ACTIVATE_EARLY=1 activates member 1 as soon as
# its own status reports finalized_ready, before the others finish.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
MINTD="${CDK_MINTD_BIN:-$REPO_ROOT/target/debug/cdk-mintd}"
MINT_CLI="${CDK_MINT_CLI_BIN:-$REPO_ROOT/target/debug/cdk-mint-cli}"
FED_DIR="${FED_DIR:-}"
MEMBERS="${MEMBERS:-4}"
THRESHOLD="${THRESHOLD:-3}"
PORT_START="${PORT_START:-31885}"
RPC_PORT_START="${RPC_PORT_START:-$((PORT_START + 100))}"
STATUS_RETRIES="${STATUS_RETRIES:-600}"
STATUS_SLEEP_SECONDS="${STATUS_SLEEP_SECONDS:-1}"
BUILD="${BUILD:-1}"
TRANSPORT="${TRANSPORT:-http}"
IROH_PORT_START="${IROH_PORT_START:-$((PORT_START + 200))}"
APPROVE_ORDER="${APPROVE_ORDER:-creator-first}"
ACTIVATE_EARLY="${ACTIVATE_EARLY:-0}"
PIDS=()

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

member_dir() {
    printf '%s/member-%s' "$FED_DIR" "$1"
}

member_work_dir() {
    printf '%s/work' "$(member_dir "$1")"
}

member_port() {
    printf '%s' "$((PORT_START + $1 - 1))"
}

member_rpc_port() {
    printf '%s' "$((RPC_PORT_START + $1 - 1))"
}

member_iroh_port() {
    printf '%s' "$((IROH_PORT_START + $1 - 1))"
}

# Over HTTP the public and federation API URLs must differ, so they spell the same
# local port two ways. Over Iroh both are the member's Iroh endpoint.
member_url() {
    case "$TRANSPORT" in
        iroh) sed -n '1p' "$(member_dir "$1")/endpoint.url" ;;
        *) printf 'http://localhost:%s' "$(member_port "$1")" ;;
    esac
}

member_ticket() {
    sed -n '1p' "$(member_dir "$1")/endpoint.ticket"
}

# Flags that pick each member's federation API URL and URL policy.
setup_url_args() {
    case "$TRANSPORT" in
        iroh) ;;
        *) printf '%s\n' --federation-api-url "$(member_federation_url "$1")" --allow-insecure-localhost ;;
    esac
}

member_federation_url() {
    printf 'http://127.0.0.1:%s' "$(member_port "$1")"
}

member_activated_dir() {
    printf '%s/federation-setup/state/activated' "$(member_work_dir "$1")"
}

setup_cli() {
    local member="$1"
    shift
    "$MINT_CLI" \
        --addr "http://127.0.0.1:$(member_rpc_port "$member")" \
        --work-dir "$FED_DIR/cli" \
        "$@"
}

stop_all() {
    local member pid
    for member in "${!PIDS[@]}"; do
        pid="${PIDS[$member]}"
        kill -INT "$pid" 2>/dev/null || true
    done
    for member in "${!PIDS[@]}"; do
        wait "${PIDS[$member]}" 2>/dev/null || true
    done
    PIDS=()
}
trap stop_all EXIT
trap 'exit 130' INT TERM

write_member_config() {
    local member="$1" output secret_path
    output="$(member_dir "$member")/member.toml"
    secret_path="$(member_dir "$member")/mint-seed"
    (umask 077; openssl rand -hex 32 | tr -d '\n' >"$secret_path")
    {
        printf '[info]\n'
        printf 'url = "%s"\n' "$(member_url "$member")"
        printf 'listen_host = "127.0.0.1"\n'
        printf 'listen_port = %s\n' "$(member_port "$member")"
        if [[ "$TRANSPORT" == "iroh" ]]; then
            printf 'http_enabled = false\n'
        fi
        printf 'seed = "file:%s"\n' "$secret_path"
        printf 'enable_info_page = false\n\n'
        if [[ "$TRANSPORT" == "iroh" ]]; then
            write_iroh_section "$member"
        fi
        printf '[mint_info]\n'
        printf 'name = "gRPC setup member %s"\n' "$member"
        printf 'description = "Federation set up over the management RPC"\n\n'
        printf '[database]\nengine = "sqlite"\n\n'
        printf '[[payment_backend]]\nbackend = "fakewallet"\nunit = "sat"\n'
        printf 'min_mint = 1\nmax_mint = 500000\nmin_melt = 1\nmax_melt = 500000\n\n'
        printf '[fake_wallet]\nsupported_units = ["sat"]\nfee_percent = 0.0\n'
        printf 'reserve_fee_min = 1\nmin_delay_time = 0\nmax_delay_time = 0\n'
        printf 'shared_incoming_payment_dir = "%s"\n\n' "$FED_DIR/fake-payment-network"
        printf '[mint_management_rpc]\nenabled = true\naddress = "127.0.0.1"\n'
        printf 'port = %s\nallow_insecure = true\n\n' "$(member_rpc_port "$member")"
        printf '[federation]\nenabled = true\n'
        printf 'allow_development_payment_observation_policy = true\n\n'
        printf '[federation.setup]\nenabled = true\n\n'
        printf '[federation.dkg]\nmax_ticks = 1200\nretry_delay_ms = 250\n'
        printf 'ceremony_timeout_secs = 600\n\n'
        printf '[federation.peer_sync]\naleph_bft_active_unit_interval_ms = 100\n'
        printf 'operation_submission_timeout_secs = 180\n'
    } >"$output"
    chmod 600 "$output"
    "$MINTD" --work-dir "$(member_work_dir "$member")" config init --new-mint --file "$output" \
        >"$(member_dir "$member")/config-init.log"
}

# Iroh-only members find each other through static tickets for every other member.
write_iroh_section() {
    local member="$1" peer
    printf '[iroh]\nenabled = true\ngenerate_secret_key = true\ndiscovery = "static"\n'
    printf 'bind_addr = "127.0.0.1:%s"\n' "$(member_iroh_port "$member")"
    printf 'static_tickets = ['
    for peer in $(seq 1 "$MEMBERS"); do
        [[ "$peer" == "$member" ]] && continue
        printf '"%s",' "$(member_ticket "$peer")"
    done
    printf ']\n\n'
}

create_iroh_identities() {
    local member output
    for member in $(seq 1 "$MEMBERS"); do
        output="$("$MINTD" --work-dir "$(member_work_dir "$member")" iroh ticket \
            --bind-addr "127.0.0.1:$(member_iroh_port "$member")")"
        sed -n '1p' <<<"$output" >"$(member_dir "$member")/endpoint.url"
        sed -n '2p' <<<"$output" >"$(member_dir "$member")/endpoint.ticket"
        [[ "$(sed -n '1p' "$(member_dir "$member")/endpoint.url")" =~ ^iroh://[a-z0-9]+$ ]] \
            || die "member $member Iroh URL is invalid"
    done
}

# The smoke wallet dials members over Iroh, so it needs its own stored config.
write_operator_config() {
    local output secret_path url peer
    output="$FED_DIR/operator.toml"
    secret_path="$FED_DIR/operator-seed"
    (umask 077; openssl rand -hex 32 | tr -d '\n' >"$secret_path")
    url="$("$MINTD" --work-dir "$FED_DIR/operator" iroh ticket --bind-addr 127.0.0.1:0 | sed -n '1p')"
    {
        printf '[info]\nurl = "%s"\nhttp_enabled = false\nseed = "file:%s"\n\n' "$url" "$secret_path"
        printf '[iroh]\nenabled = true\ngenerate_secret_key = true\ndiscovery = "static"\n'
        printf 'bind_addr = "127.0.0.1:0"\nstatic_tickets = ['
        for peer in $(seq 1 "$MEMBERS"); do
            printf '"%s",' "$(member_ticket "$peer")"
        done
        printf ']\n\n[database]\nengine = "sqlite"\n\n'
        printf '[[payment_backend]]\nbackend = "fakewallet"\nunit = "sat"\n'
        printf 'min_mint = 1\nmax_mint = 500000\nmin_melt = 1\nmax_melt = 500000\n\n'
        printf '[fake_wallet]\nsupported_units = ["sat"]\nfee_percent = 0.0\n'
        printf 'reserve_fee_min = 1\nmin_delay_time = 0\nmax_delay_time = 0\n'
    } >"$output"
    chmod 600 "$output"
    "$MINTD" --work-dir "$FED_DIR/operator" config init --new-mint --file "$output" \
        >"$FED_DIR/operator-config-init.log"
}

start_member() {
    local member="$1"
    (
        exec "$MINTD" --work-dir "$(member_work_dir "$member")"
    ) >"$(member_dir "$member")/mintd.log" 2>&1 &
    PIDS[$member]=$!
}

wait_for_setup_rpc() {
    local member="$1" attempt
    for attempt in $(seq 1 "$STATUS_RETRIES"); do
        kill -0 "${PIDS[$member]}" 2>/dev/null \
            || die "member $member exited; see $(member_dir "$member")/mintd.log"
        if setup_cli "$member" federation-setup status --json \
            >"$(member_dir "$member")/status.json" 2>/dev/null; then
            return 0
        fi
        sleep "$STATUS_SLEEP_SECONDS"
    done
    die "member $member setup RPC did not become reachable"
}

# Wait until every listed member (default: all) reports finalized_ready.
wait_for_all_finalized() {
    local attempt member all_ready
    local members=("$@")
    ((${#members[@]} > 0)) || members=($(seq 1 "$MEMBERS"))
    for attempt in $(seq 1 "$STATUS_RETRIES"); do
        all_ready=true
        for member in "${members[@]}"; do
            if ! setup_cli "$member" federation-setup status --json \
                >"$(member_dir "$member")/status.json" 2>/dev/null; then
                all_ready=false
                continue
            fi
            [[ "$(jq -r '.dkg.finalized_ready // false' "$(member_dir "$member")/status.json")" == "true" ]] \
                || all_ready=false
        done
        [[ "$all_ready" == "true" ]] && return 0
        sleep "$STATUS_SLEEP_SECONDS"
    done
    for member in "${members[@]}"; do
        printf 'member %s: %s\n' "$member" \
            "$(jq -c '{participant_phase, dkg: .dkg.phase, error: .dkg.error}' "$(member_dir "$member")/status.json" 2>/dev/null || echo unknown)" >&2
    done
    die "key generation did not finish on every member"
}

wait_for_running_member() {
    local member="$1" attempt
    for attempt in $(seq 1 "$STATUS_RETRIES"); do
        kill -0 "${PIDS[$member]}" 2>/dev/null \
            || die "member $member exited after activation; see $(member_dir "$member")/mintd.log"
        if setup_cli "$member" get-info >"$(member_dir "$member")/get-info.log" 2>/dev/null; then
            [[ "$TRANSPORT" == "iroh" ]] && return 0
            curl --fail --silent "$(member_url "$member")/v1/keysets" \
                >"$(member_dir "$member")/keysets.json" && return 0
        fi
        sleep "$STATUS_SLEEP_SECONDS"
    done
    die "member $member did not come back as a running federation member"
}

activate_member() {
    setup_cli "$1" federation-setup activate >"$(member_dir "$1")/activate.log" \
        2>"$(member_dir "$1")/activate-warning.log"
}

for command in cargo cmp curl jq openssl seq; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done
[[ "$MEMBERS" =~ ^[1-9][0-9]*$ ]] || die "MEMBERS must be positive"
[[ "$THRESHOLD" =~ ^[1-9][0-9]*$ ]] || die "THRESHOLD must be positive"
((THRESHOLD <= MEMBERS)) || die "THRESHOLD cannot exceed MEMBERS"
[[ "$TRANSPORT" == "http" || "$TRANSPORT" == "iroh" ]] || die "TRANSPORT must be http or iroh"
[[ "$APPROVE_ORDER" == "creator-first" || "$APPROVE_ORDER" == "creator-last" ]] \
    || die "APPROVE_ORDER must be creator-first or creator-last"
[[ "$ACTIVATE_EARLY" == "0" || "$ACTIVATE_EARLY" == "1" ]] || die "ACTIVATE_EARLY must be 0 or 1"

cd "$REPO_ROOT"
if [[ "$BUILD" == "1" ]]; then
    mintd_features="federation-test-utils,sqlite"
    [[ "$TRANSPORT" == "iroh" ]] && mintd_features="$mintd_features,iroh"
    cargo build -p cdk-mintd --features "$mintd_features"
    cargo build -p cdk-mint-rpc --bin cdk-mint-cli
fi

if [[ -z "$FED_DIR" ]]; then
    mkdir -p "$REPO_ROOT/target"
    FED_DIR="$(mktemp -d "$REPO_ROOT/target/cdk-fed-setup-grpc.XXXXXX")"
else
    mkdir -- "$FED_DIR" \
        || die "FED_DIR must name a new directory so existing data is never overwritten"
fi
mkdir -p "$FED_DIR/cli" "$FED_DIR/invitations" "$FED_DIR/fake-payment-network" "$FED_DIR/operator"
printf 'Federation directory: %s\n' "$FED_DIR"

printf 'Starting %s fresh members in federation setup mode over %s...\n' "$MEMBERS" "$TRANSPORT"
for member in $(seq 1 "$MEMBERS"); do
    mkdir -p "$(member_work_dir "$member")"
done
if [[ "$TRANSPORT" == "iroh" ]]; then
    create_iroh_identities
    write_operator_config
fi
for member in $(seq 1 "$MEMBERS"); do
    write_member_config "$member"
    start_member "$member"
done
for member in $(seq 1 "$MEMBERS"); do
    wait_for_setup_rpc "$member"
    [[ "$(jq -r '.initialized' "$(member_dir "$member")/status.json")" == "false" ]] \
        || die "member $member was not a fresh setup"
done

printf 'Creating the setup on member 1 over gRPC...\n'
setup_cli 1 federation-setup create \
    --members "$MEMBERS" \
    --threshold "$THRESHOLD" \
    --network regtest \
    --output-dir "$FED_DIR/invitations" \
    $(setup_url_args 1) \
    >"$(member_dir 1)/create.log"

printf 'Joining members 2..%s over gRPC...\n' "$MEMBERS"
for member in $(seq 2 "$MEMBERS"); do
    setup_cli "$member" federation-setup join \
        --invitation-file "$FED_DIR/invitations/member-$member.invite" \
        $(setup_url_args "$member") \
        >"$(member_dir "$member")/join.log"
done

setup_cli 1 federation-setup propose >"$(member_dir 1)/propose.log"
proposal_hash="$(sed -n 's/^proposal_hash: //p' "$(member_dir 1)/propose.log")"
[[ "$proposal_hash" =~ ^[0-9a-f]{64}$ ]] || die "proposal hash is invalid"
case "$APPROVE_ORDER" in
    creator-last) approve_order=($(seq 2 "$MEMBERS") 1) ;;
    *) approve_order=($(seq 1 "$MEMBERS")) ;;
esac
printf 'Proposal %s; every member reviews and approves (%s)...\n' "$proposal_hash" "$APPROVE_ORDER"
for member in "${approve_order[@]}"; do
    setup_cli "$member" federation-setup review --json >"$(member_dir "$member")/review.json"
    [[ "$(jq -r '.proposal_hash' "$(member_dir "$member")/review.json")" == "$proposal_hash" ]] \
        || die "member $member reviewed another proposal"
    setup_cli "$member" federation-setup approve --proposal-hash "$proposal_hash" \
        >"$(member_dir "$member")/approve.log"
done

dkg_started_at="$SECONDS"
activate_members=($(seq 1 "$MEMBERS"))
if [[ "$ACTIVATE_EARLY" == "1" ]]; then
    printf 'Activating member 1 as soon as it reports finalized_ready...\n'
    wait_for_all_finalized 1
    activate_member 1
    activate_members=($(seq 2 "$MEMBERS"))
fi
printf 'Waiting for key generation to finish on members %s...\n' "${activate_members[*]}"
wait_for_all_finalized "${activate_members[@]}"
printf 'Key generation finished in %ss\n' "$((SECONDS - dkg_started_at))"

printf 'Activating members %s over gRPC...\n' "${activate_members[*]}"
for member in "${activate_members[@]}"; do
    activate_member "$member"
done
for member in $(seq 1 "$MEMBERS"); do
    cmp -s "$(member_activated_dir 1)/federation-public.json" \
        "$(member_activated_dir "$member")/federation-public.json" \
        || die "member $member activated another public config"
done

printf 'Waiting for each daemon to come back as a running federation member...\n'
for member in $(seq 1 "$MEMBERS"); do
    wait_for_running_member "$member"
done
if [[ "$TRANSPORT" == "http" ]]; then
    expected_keysets="$(jq -c '[.keysets[].id] | sort' "$(member_dir 1)/keysets.json")"
    [[ "$expected_keysets" != "[]" ]] || die "member 1 serves no keysets"
    for member in $(seq 2 "$MEMBERS"); do
        [[ "$(jq -c '[.keysets[].id] | sort' "$(member_dir "$member")/keysets.json")" == "$expected_keysets" ]] \
            || die "member $member serves different keysets"
    done
    printf 'All members run the federation keyset %s\n' "$expected_keysets"
fi

printf 'Running paid mint/swap/melt smoke operations...\n'
"$MINTD" --work-dir "$FED_DIR/operator" federation smoke-operations \
    --public-config "$(member_activated_dir 1)/federation-public.json" \
    --private-config "$(member_activated_dir 1)/federation-private.json" \
    --scenario standard \
    --unit sat \
    --quote-retries 300 \
    --quote-sleep-ms 100 \
    --operation-timeout-seconds 900 \
    >"$FED_DIR/smoke.log"

printf 'federation setup over gRPC passed: %s\n' "$FED_DIR"
