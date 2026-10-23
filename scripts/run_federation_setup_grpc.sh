#!/usr/bin/env bash
# End-to-end federation setup driven only through the management gRPC.
#
# Every member starts as a fresh `cdk-mintd` in federation setup mode. The
# creator, the joiners, proposal approval, key generation, and activation are all
# driven with `cdk-mint-cli federation-setup`. After activation each daemon must
# come back, in the same process, as a running federation member on the same RPC
# port, and the federation must pass the paid mint/swap/melt smoke scenario.
#
# Before the real setup, member 1 creates a throwaway setup that member 2 joins,
# and both abort it. In the real setup the coordinator replaces the last member's
# invitation before that member joins, and every member's status must show the
# same identity fingerprint the proposal review lists for it.
#
# TRANSPORT=http (default) runs federation traffic over local HTTP. TRANSPORT=iroh
# makes every member Iroh-only for enrollment, key generation, and consensus;
# the management gRPC stays on localhost TCP either way.
#
# Operators in a GUI click in any order, so two switches change the order:
# APPROVE_ORDER=creator-last approves members 2..N before the creator
# (default creator-first), and ACTIVATE_EARLY=1 activates member 1 as soon as
# its own status reports finalized_ready, before the others finish.
#
# Once the federation runs, every member is read through `cdk-mint-cli
# federation`: the federation ids must match, every member must reach every
# other one, and their digests must agree. The last member is then stopped and
# must show as unreachable while the others stay healthy.
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
        write_fakewallet_sections
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
        write_fakewallet_sections
    } >"$output"
    chmod 600 "$output"
    "$MINTD" --work-dir "$FED_DIR/operator" config init --new-mint --file "$output" \
        >"$FED_DIR/operator-config-init.log"
}

# The fake payment backend shared by member and operator configs.
write_fakewallet_sections() {
    printf '[[payment_backend]]\nbackend = "fakewallet"\nunit = "sat"\n'
    printf 'min_mint = 1\nmax_mint = 500000\nmin_melt = 1\nmax_melt = 500000\n\n'
    printf '[fake_wallet]\nsupported_units = ["sat"]\nfee_percent = 0.0\n'
    printf 'reserve_fee_min = 1\nmin_delay_time = 0\nmax_delay_time = 0\n'
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
    local attempt member
    local members=("$@") waiting=()
    ((${#members[@]} > 0)) || members=($(seq 1 "$MEMBERS"))
    waiting=("${members[@]}")
    for attempt in $(seq 1 "$STATUS_RETRIES"); do
        # finalized_ready never goes back to false, so ready members drop out.
        local still_waiting=()
        for member in "${waiting[@]}"; do
            if setup_cli "$member" federation-setup status --json \
                >"$(member_dir "$member")/status.json" 2>/dev/null \
                && [[ "$(jq -r '.dkg.finalized_ready // false' "$(member_dir "$member")/status.json")" == "true" ]]; then
                continue
            fi
            still_waiting+=("$member")
        done
        ((${#still_waiting[@]} == 0)) && return 0
        waiting=("${still_waiting[@]}")
        sleep "$STATUS_SLEEP_SECONDS"
    done
    for member in "${waiting[@]}"; do
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

# Wait until a member sees every member reachable except the optional stopped
# one, every reachable member ready, and all their digests in agreement.
wait_for_member_statuses() {
    local member="$1" stopped="${2:-0}" attempt output
    output="$(member_dir "$member")/federation-members.json"
    for attempt in $(seq 1 "$STATUS_RETRIES"); do
        if setup_cli "$member" federation members --json >"$output" 2>/dev/null \
            && jq -e --argjson members "$MEMBERS" --argjson stopped "$stopped" \
                --arg federation_id "$federation_id" '
                (.members | length) == $members
                and all(.members[];
                    if .member_id == $stopped then (.reachable | not) and (.error // "") != ""
                    else .reachable
                        and .status.federation_id == $federation_id
                        and .status.sync.ready
                    end)
                and ([.members[] | select(.local) | .member_id] | length) == 1
                and .digest_agreement.state == "converged"
                and (.digest_agreement.compared_members | length)
                    == ($members - (if $stopped > 0 then 1 else 0 end))' \
                "$output" >/dev/null; then
            return 0
        fi
        sleep "$STATUS_SLEEP_SECONDS"
    done
    jq -c '{members: [.members[] | {member_id, reachable, error, sync: .status.sync.state}], digest_agreement}' \
        "$output" >&2 2>/dev/null || true
    die "member $member did not see the expected member statuses"
}

check_federation_status_rpcs() {
    local member info status
    for member in $(seq 1 "$MEMBERS"); do
        info="$(member_dir "$member")/federation-info.json"
        status="$(member_dir "$member")/federation-status.json"
        setup_cli "$member" federation info --json >"$info"
        setup_cli "$member" federation status --json >"$status"
        setup_cli "$member" federation custody --json >"$(member_dir "$member")/federation-custody.json"
        setup_cli "$member" federation info >"$(member_dir "$member")/federation-info.log"
        [[ "$(jq -r '.federation_id' "$info")" == "$federation_id" ]] \
            || die "member $member reports another federation id"
        [[ "$(jq -r '.config_digest' "$info")" == "$config_digest" ]] \
            || die "member $member reports another config digest"
        [[ "$(jq -r '.local_member_id' "$info")" == "$member" ]] \
            || die "member $member reports another local member id"
        [[ "$(jq -r '.members | length' "$info")" == "$MEMBERS" ]] \
            || die "member $member reports another member count"
        [[ "$(jq -r '.member_id' "$status")" == "$member" ]] \
            || die "member $member local status names another member"
        [[ "$(jq -r '.federation_id' "$status")" == "$federation_id" ]] \
            || die "member $member local status names another federation"
        [[ "$(jq -r '.checkpoint.audit_mismatch' "$status")" == "false" ]] \
            || die "member $member reports a digest alert"
    done
    for member in $(seq 1 "$MEMBERS"); do
        wait_for_member_statuses "$member"
    done
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
    # One build of both packages compiles the shared crates once.
    features="cdk-mintd/federation-test-utils,cdk-mintd/sqlite"
    [[ "$TRANSPORT" == "iroh" ]] && features="$features,cdk-mintd/iroh"
    cargo build -p cdk-mintd -p cdk-mint-rpc --bins --features "$features"
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

printf 'Creating a throwaway setup, joining member 2, then aborting it on both...\n'
setup_cli 1 federation-setup create \
    --members "$MEMBERS" \
    --threshold "$THRESHOLD" \
    --network regtest \
    --output-dir "$FED_DIR/aborted-invitations" \
    $(setup_url_args 1) \
    >"$(member_dir 1)/aborted-create.log"
aborted_setup_id="$(sed -n 's/^setup_id: //p' "$(member_dir 1)/aborted-create.log")"
setup_cli 2 federation-setup join \
    --invitation-file "$FED_DIR/aborted-invitations/member-2.invite" \
    $(setup_url_args 2) \
    >"$(member_dir 2)/aborted-join.log"
for member in 2 1; do
    setup_cli "$member" federation-setup abort --setup-id "$aborted_setup_id" \
        >"$(member_dir "$member")/abort.log"
    setup_cli "$member" federation-setup status --json >"$(member_dir "$member")/status.json"
    [[ "$(jq -r '.initialized' "$(member_dir "$member")/status.json")" == "false" ]] \
        || die "member $member still reports a setup after aborting it"
done

printf 'Creating the setup on member 1 over gRPC...\n'
setup_cli 1 federation-setup create \
    --members "$MEMBERS" \
    --threshold "$THRESHOLD" \
    --network regtest \
    --output-dir "$FED_DIR/invitations" \
    $(setup_url_args 1) \
    >"$(member_dir 1)/create.log"
[[ "$(sed -n 's/^setup_id: //p' "$(member_dir 1)/create.log")" != "$aborted_setup_id" ]] \
    || die "the new setup reused the aborted setup ID"

printf 'Replacing member %s invitation over gRPC...\n' "$MEMBERS"
replaced_invitation="$FED_DIR/invitations/member-$MEMBERS.invite"
cp -p "$replaced_invitation" "$replaced_invitation.original"
setup_cli 1 federation-setup replace-invitation \
    --member "$MEMBERS" \
    --output "$replaced_invitation" \
    >"$(member_dir 1)/replace-invitation.log"
! cmp -s "$replaced_invitation" "$replaced_invitation.original" \
    || die "the replacement invitation matches the original"

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
    setup_cli "$member" federation-setup status --json >"$(member_dir "$member")/status.json"
    [[ "$(jq -r '.identity_fingerprint' "$(member_dir "$member")/status.json")" \
        == "$(jq -r --argjson member "$member" \
            '.members[] | select(.member_id == $member) | .identity_fingerprint' \
            "$(member_dir "$member")/review.json")" ]] \
        || die "member $member status shows another identity fingerprint than the review"
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

printf 'Reading federation status from every member over gRPC...\n'
setup_cli 1 federation info --json >"$(member_dir 1)/federation-info.json"
federation_id="$(jq -r '.federation_id' "$(member_dir 1)/federation-info.json")"
config_digest="$(jq -r '.config_digest' "$(member_dir 1)/federation-info.json")"
[[ -n "$federation_id" && "$federation_id" != "null" ]] || die "member 1 reports no federation id"
check_federation_status_rpcs
printf 'Every member reaches every other member and their digests agree (%s payment reports on member 1)\n' \
    "$(jq -r '.payment_observations.total_reports' "$(member_dir 1)/federation-status.json")"

stopped_member="$MEMBERS"
printf 'Stopping member %s; the others must report it unreachable...\n' "$stopped_member"
kill -INT "${PIDS[$stopped_member]}" 2>/dev/null || true
wait "${PIDS[$stopped_member]}" 2>/dev/null || true
unset 'PIDS[$stopped_member]'
for member in $(seq 1 "$((MEMBERS - 1))"); do
    wait_for_member_statuses "$member" "$stopped_member"
done
printf 'Members 1..%s report member %s unreachable and stay healthy\n' "$((MEMBERS - 1))" "$stopped_member"

printf 'federation setup over gRPC passed: %s\n' "$FED_DIR"
