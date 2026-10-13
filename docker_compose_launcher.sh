#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# Build images and generate setup separately; see README.md.
# Usage: bash docker_compose_launcher.sh [run|check|logs|down] [--measure]
# REPS=1, STARTUP_TIMEOUT=1800 and RUN_TIMEOUT=7200 control execution.
die() { echo "Error: $*" >&2; exit 1; }
ACTION=${1:-run}
MEASURE=0
if [[ "$ACTION" == --measure ]]; then
    ACTION=run
    MEASURE=1
fi
if [[ "$ACTION" == --help || "$ACTION" == -h ]]; then
    echo "Usage: bash docker_compose_launcher.sh [run|check|logs|down] [--measure]"
    exit 0
fi
(( $# <= 2 )) || die "Too many arguments."
if [[ -n "${2:-}" ]]; then
    [[ "$2" == --measure && "$ACTION" == run ]] || die "Expected run --measure."
    MEASURE=1
fi
COMPOSE=(docker compose --project-directory "$PWD" -f "$PWD/docker-compose.yml")
case "$ACTION" in
    check) docker info >/dev/null; "${COMPOSE[@]}" config --quiet; exit 0 ;;
    logs) "${COMPOSE[@]}" logs --no-color --tail=100; exit 0 ;;
    down) "${COMPOSE[@]}" down --remove-orphans; exit 0 ;;
    run) ;;
    *) die "Unknown action: $ACTION. Use run, check, logs or down." ;;
esac

for name in REPS STARTUP_TIMEOUT RUN_TIMEOUT; do
    value="${!name:-}"
    [[ -z "$value" || "$value" =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer."
done
REPS=${REPS:-1}
STARTUP_TIMEOUT=${STARTUP_TIMEOUT:-1800}
RUN_TIMEOUT=${RUN_TIMEOUT:-7200}
mkdir -p measurments measurments_client measurments_work1 measurments_work2 measurments_work3

# Setup is a separate manual step documented in README.md.
for file in artifacts/circuits/JRPC_complete_dynamic_optimized.arith \
    artifacts/circuits/input_layout_complete.txt \
    examples/rss_snark/inst_folder/inst_13_0_1/test.{root,0,1,2}; do
    [[ -s "$file" ]] || die "Missing $file. Follow the setup instructions in README.md."
done
if (( MEASURE )); then
    [[ -x .venv/bin/python ]] && .venv/bin/python -c 'import docker' ||
        die "Prepare the optional measurement environment as described in README.md."
fi

MEAS_PID=''
stop_metrics() {
    if [[ -n "$MEAS_PID" ]]; then
        kill -TERM "$MEAS_PID" 2>/dev/null || true
        wait "$MEAS_PID" 2>/dev/null || true
        MEAS_PID=''
    fi
}
finish() {
    local code=$?
    stop_metrics
    if (( code != 0 )); then
        "${COMPOSE[@]}" logs --no-color --tail=60 >&2 || true
        echo "Containers retained for inspection. Use the logs and down actions." >&2
    fi
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
wait_ready() {
    local service="$1" probe="$2" deadline=$((SECONDS + STARTUP_TIMEOUT))
    echo "Waiting for $service..."
    until "${COMPOSE[@]}" exec -T "$service" sh -c "$probe" >/dev/null 2>&1; do
        [[ -n "$("${COMPOSE[@]}" ps --status running -q "$service")" ]] ||
            die "$service stopped during startup."
        (( SECONDS < deadline )) || die "$service readiness timed out."
        sleep 2
    done
}
for ((run=1; run<=REPS; run++)); do
    echo "Run $run/$REPS"
    "${COMPOSE[@]}" down --remove-orphans
    "${COMPOSE[@]}" up -d --no-build server worker1 worker2 worker3 coordinator
    wait_ready server 'test -s /certs/root-ca.pem && ss -lnt | grep -q ":8443 "'
    for service in coordinator worker1 worker2 worker3; do
        # Inspect listeners without consuming the protocol's single accept().
        wait_ready "$service" 'ss -lnt | grep -q ":8220 "'
    done
    wait_ready coordinator 'test -s /app/app/files/capture.pcap'
    if (( MEASURE )); then
        .venv/bin/python measurment_docker_streaming.py "$run" &
        MEAS_PID=$!
    fi
    RUN_ID="$run" "${COMPOSE[@]}" up -d --no-build --no-deps client
    deadline=$((SECONDS + RUN_TIMEOUT))
    while :; do
        complete=1
        for service in client coordinator; do
            id=$("${COMPOSE[@]}" ps -a -q "$service")
            [[ -n "$id" ]] || die "Missing $service container."
            state=$(docker inspect --format '{{.State.Status}}' "$id")
            case "$state" in
                exited)
                    code=$(docker inspect --format '{{.State.ExitCode}}' "$id")
                    (( code == 0 )) || die "$service exited with status $code." ;;
                running|created) complete=0 ;;
                *) die "$service entered unexpected state: $state" ;;
            esac
        done
        (( complete == 0 )) || break
        (( SECONDS < deadline )) || die "Run exceeded RUN_TIMEOUT=$RUN_TIMEOUT."
        sleep 2
    done
    stop_metrics
    "${COMPOSE[@]}" logs --no-color > "measurments/run_${run}.log"
    "${COMPOSE[@]}" down --remove-orphans
done
echo "Completed. Client results: measurments_client/; service logs: measurments/"
