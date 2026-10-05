#!/usr/bin/env bash
#
# leitwacht-agent CE — integration test runner.
#
# Top-level driver that exercises both the CE end-to-end harness
# (tests/e2e/run.sh, four cases against real Docker containers) and
# the agentcore enforcer integration tests (real eBPF + containerd).
# Designed to be run on a dedicated Linux test box.
#
# Requirements:
#   - Linux x86_64, kernel >= 5.15
#   - root (eBPF + nftables)
#   - go >= 1.27
#   - docker, jq, curl, python3
#   - (optional) containerd for the agentcore-integration phase
#
# Run from anywhere — the script resolves the repo root from its own
# location, so a fresh clone works without further configuration:
#
#   sudo bash tests/integration/run.sh                  # CE e2e + agentcore integration
#   sudo bash tests/integration/run.sh ce-only          # CE e2e only (~2 min)
#   sudo bash tests/integration/run.sh agentcore-only   # agentcore enforcer integration
#
# Each phase tees stdout+stderr to a per-phase log under
# $LOGDIR (default /tmp/leitwacht-integration-<timestamp>/).
# Copy logs off the host with the scp line printed at the end.

set -uo pipefail

# Resolve the repo root from the script's location so the runner works
# regardless of where the repo is cloned.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

GO_BIN="${GO_BIN:-$(command -v go || echo /usr/local/go/bin/go)}"
PATH="$(dirname "$GO_BIN"):$PATH"
export PATH

TS="$(date +%Y%m%d-%H%M%S)"
LOGDIR="${LOGDIR:-/tmp/leitwacht-integration-$TS}"
mkdir -p "$LOGDIR"

# Telemetry collected for the summary.
PHASES=()
RESULTS=()

c_red()   { printf '\033[31m%s\033[0m' "$*"; }
c_green() { printf '\033[32m%s\033[0m' "$*"; }
c_cyan()  { printf '\033[36m%s\033[0m' "$*"; }

banner() {
  printf '\n%s\n' "$(c_cyan "──── $* ────")"
}

# Run a phase: arg 1 is the phase label (also log filename), arg 2..N
# is the command + args. Tees stdout+stderr to both terminal and log
# file. Records the result in $RESULTS without aborting on failure so
# the runner can continue with later phases.
run_phase() {
  local label="$1"; shift
  local logfile="$LOGDIR/${label}.log"

  banner "$label"
  printf 'log file: %s\n\n' "$logfile"

  local start_epoch=$(date +%s)
  set +e
  ( "$@" ) 2>&1 | tee "$logfile"
  local rc=${PIPESTATUS[0]}
  set -e
  local elapsed=$(( $(date +%s) - start_epoch ))

  PHASES+=("$label")
  if [[ $rc -eq 0 ]]; then
    RESULTS+=("$(c_green PASS) $label (${elapsed}s)")
  else
    RESULTS+=("$(c_red FAIL) $label (${elapsed}s, rc=$rc)")
  fi
  return 0
}

# ---------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------

phase_environment() {
  echo "host: $(hostname) $(uname -r) $(. /etc/os-release; echo $PRETTY_NAME)"
  echo "go:   $($GO_BIN version 2>/dev/null || echo MISSING)"
  echo "selinux: $(getenforce 2>/dev/null || echo n/a)"
  echo "docker: $(systemctl is-active docker 2>/dev/null || echo missing)"
  echo "containerd: $(systemctl is-active containerd 2>/dev/null || echo missing)"
  echo "kernel modules:"
  lsmod | awk '$1 ~ /^(bpf|nft|cgroup)/ {print "  "$1}' | head -20
  echo "repo: $REPO ($([[ -d $REPO/.git ]] && echo present || echo MISSING))"
}

phase_preflight() {
  # Start containerd before docker. On distros where docker uses
  # containerd as its runtime (Fedora, modern Debian), `docker run`
  # dials the containerd socket and times out if it's down — manifests
  # as `transport: Error while dialing: dial unix:///run/containerd/...`
  # in container creation, not at docker daemon start.
  #
  # Note: `systemctl start` returns when the unit transitions to
  # `active`, not when the socket is actually accepting connections.
  # Wait for the socket explicitly so `docker run` (which dials it
  # immediately) doesn't race the readiness window.
  echo "starting containerd..."
  if systemctl start containerd 2>/dev/null; then
    for i in $(seq 1 30); do
      [[ -S /run/containerd/containerd.sock ]] && break
      sleep 0.1
    done
    if [[ ! -S /run/containerd/containerd.sock ]]; then
      echo "containerd socket /run/containerd/containerd.sock did not appear after 3s"
    fi
  else
    echo "(no containerd unit; ignoring — docker may run standalone)"
  fi

  echo "starting docker..."
  systemctl start docker
  systemctl is-active docker

  # Same wait for docker — its API socket lags `is-active` on cold starts.
  for i in $(seq 1 30); do
    docker info >/dev/null 2>&1 && break
    sleep 0.1
  done
  if ! docker info >/dev/null 2>&1; then
    echo "docker daemon did not become ready after 3s"
  fi

  echo "setenforce 0 (will be restored at end)..."
  if [[ "$(getenforce)" == "Enforcing" ]]; then
    setenforce 0
    SELINUX_RESTORE=1
  else
    SELINUX_RESTORE=0
  fi
  echo "selinux now: $(getenforce)"

  echo "pulling curlimages/curl:8.5.0 to warm Docker cache..."
  docker pull curlimages/curl:8.5.0 || echo "(pull failed; e2e cases may be slow)"

  # Cleanup any leftovers from previous runs.
  echo "cleaning up any prior leitwacht containers..."
  docker ps -aq --filter 'name=leitwacht-e2e' | xargs -r docker rm -f
}

phase_ce_e2e() {
  cd "$REPO"
  KEEP_LOGS=1 LOG_LEVEL=debug WORK="$LOGDIR/e2e-sandbox" \
    bash tests/e2e/run.sh
}

phase_agentcore_integration() {
  echo "starting containerd..."
  if ! systemctl start containerd 2>/dev/null; then
    echo "containerd not available; skipping agentcore integration"
    return 0
  fi
  systemctl is-active containerd

  echo "pulling alpine:3.20 via ctr..."
  ctr images pull docker.io/library/alpine:3.20 >/dev/null 2>&1 || \
    echo "(ctr pull failed; tests using it may skip)"

  cd "$REPO"
  $GO_BIN test -tags='integration linux' -count=1 -v ./agentcore/enforcer/... 2>&1
}

phase_dmesg_review() {
  echo "kernel messages from this run window:"
  # Carve TS=YYYYMMDD-HHMMSS into a properly-formatted date dmesg --since accepts.
  local ts_date="${TS%%-*}"          # YYYYMMDD
  local hh="${TS##*-}"               # HHMMSS
  local since="${ts_date} ${hh:0:2}:${hh:2:2}:00"
  dmesg --since "$since" 2>/dev/null \
    | grep -iE 'bpf|nft|leitwacht|leitwacht-initc|avc:' \
    | head -50 \
    || echo "(no relevant kernel messages, or dmesg lacks --since support)"
}

phase_cleanup() {
  echo "stopping docker / containerd..."
  systemctl stop docker 2>/dev/null || true
  systemctl stop containerd 2>/dev/null || true

  if [[ "${SELINUX_RESTORE:-0}" == "1" ]]; then
    echo "restoring SELinux to Enforcing..."
    setenforce 1
    echo "selinux now: $(getenforce)"
  fi

  echo "killing leftover agent-ce processes..."
  pkill -TERM -f 'bin/agent-ce' 2>/dev/null || true
  sleep 1
  pkill -KILL -f 'bin/agent-ce' 2>/dev/null || true

  echo "removing leftover test containers..."
  docker ps -aq --filter 'name=leitwacht-e2e' 2>/dev/null | xargs -r docker rm -f 2>/dev/null || true

  echo "removing leftover nftables tables (leitwacht-prefixed)..."
  nft list tables 2>/dev/null | awk '/leitwacht/ {print $2, $3}' | while read -r fam name; do
    [[ -z "$fam" ]] && continue
    echo "  delete table $fam $name"
    nft delete table "$fam" "$name" 2>/dev/null || true
  done
}

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
  echo "must run as root (eBPF + nftables); try: sudo bash $0" >&2
  exit 1
fi

mode="${1:-all}"

run_phase environment phase_environment
run_phase preflight phase_preflight

case "$mode" in
  all)
    run_phase ce_e2e phase_ce_e2e
    run_phase agentcore_integration phase_agentcore_integration
    ;;
  ce-only)
    run_phase ce_e2e phase_ce_e2e
    ;;
  agentcore-only)
    run_phase agentcore_integration phase_agentcore_integration
    ;;
  *)
    echo "unknown mode: $mode (want: all | ce-only | agentcore-only)" >&2
    exit 2
    ;;
esac

run_phase dmesg_review phase_dmesg_review
run_phase cleanup phase_cleanup

# Summary.
banner "summary"
for r in "${RESULTS[@]}"; do
  printf '  %s\n' "$r"
done

echo
echo "logs: $LOGDIR"
ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [[ -n "$ip" ]]; then
  echo "scoop them back with:"
  echo "  scp -r ${USER:-root}@${ip}:${LOGDIR} /tmp/"
fi
echo

# Mirror the summary into a top-level file so the rsync-back picks it up.
{
  printf 'leitwacht-integration run %s\n' "$TS"
  printf 'mode: %s\n' "$mode"
  printf 'host: %s %s\n\n' "$(hostname)" "$(uname -r)"
  for r in "${RESULTS[@]}"; do
    # strip ANSI for the file copy
    printf '%s\n' "$r" | sed 's/\x1b\[[0-9;]*m//g'
  done
} > "$LOGDIR/SUMMARY.txt"

# Non-zero exit if any phase failed (excluding cleanup).
fail=0
for r in "${RESULTS[@]}"; do
  if [[ "$r" == *FAIL* ]]; then
    fail=1
  fi
done
exit $fail
