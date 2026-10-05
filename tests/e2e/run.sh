#!/usr/bin/env bash
#
# leitwacht-agent CE — end-to-end smoke test.
#
# Builds agent-ce, runs it as a host process against a tmp YAML, drives
# real Docker containers through it, and asserts on the resulting NDJSON
# stream + Prometheus counters.
#
# Requirements:
#   - Linux x86_64, kernel ≥ 5.15
#   - Docker daemon running and reachable
#   - root (eBPF + nftables)
#   - go ≥ 1.27 in PATH
#   - curl, jq
#
# Usage:
#   sudo -E ./tests/e2e/run.sh                  # all cases
#   sudo -E ./tests/e2e/run.sh allow_block      # one case
#
# Each case is a function prefixed with `case_`. Cases run in their own
# sandbox dir under $WORK and tear down the agent + containers on exit.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/bin/agent-ce"
WORK="${WORK:-$(mktemp -d -t leitwacht-e2e.XXXXXX)}"
LOG_LEVEL="${LOG_LEVEL:-info}"
METRICS_PORT="${METRICS_PORT:-19090}"
KEEP_LOGS="${KEEP_LOGS:-0}"

log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()   { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# All cases use sleep+curl (instead of bare curl) so the container outlives
# the agent's enforcement-attach window (~200ms for eBPF load + netns
# wiring, longer under load). A direct `docker run curlimages/curl …` can
# exit in <100ms — racing the watcher event and leaving zero enforcers /
# zero violations. We also use httpbin.org as the deny target rather than
# evil.example.com: httpbin returns a real 200, so any failure observed
# in the test came from leitwacht's DNS proxy / cgroup attach, not from
# public DNS naturally NXDOMAIN'ing the request.
ATTACH_DELAY="${ATTACH_DELAY:-3}"

require() {
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || fail "missing required tool: $c"
  done
}

build_agent() {
  log "building agent-ce → $BIN"
  cd "$REPO"
  CGO_ENABLED=0 go build -o "$BIN" ./ce/cmd/agent-ce
  [[ -x "$BIN" ]] || fail "build did not produce $BIN"
}

# Spawn the agent with the given rules.yaml. Sets globals AGENT_PID and
# AGENT_LOG. Caller is responsible for stop_agent on exit.
start_agent() {
  local rules="$1"
  local sandbox="$2"
  AGENT_LOG="$sandbox/agent.log"

  log "starting agent-ce (pid will be in $sandbox/pid, log in $AGENT_LOG)"

  LEITWACHT_CE_RULES_PATH="$rules" \
  LEITWACHT_CE_CONTAINER_RUNTIME=docker \
  LEITWACHT_CE_DEFAULT_ACTION=block \
  LEITWACHT_CE_DNS_UPSTREAM="${LEITWACHT_CE_DNS_UPSTREAM:-1.1.1.1:53,8.8.8.8:53}" \
  LEITWACHT_CE_PROM_ADDR=":$METRICS_PORT" \
  LEITWACHT_CE_LOG_LEVEL="$LOG_LEVEL" \
  HOSTNAME_OVERRIDE="e2e-host" \
    "$BIN" >"$AGENT_LOG" 2>&1 &

  AGENT_PID=$!
  echo "$AGENT_PID" >"$sandbox/pid"

  # Wait up to 10s for /healthz.
  local n=0
  until curl -fsS "http://127.0.0.1:$METRICS_PORT/healthz" >/dev/null 2>&1; do
    sleep 0.2
    n=$((n+1))
    if (( n > 50 )); then
      log "agent did not come up; tail of log:"
      tail -n 40 "$AGENT_LOG" >&2 || true
      fail "agent /healthz timeout"
    fi
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
      log "agent died during startup; full log:"
      cat "$AGENT_LOG" >&2 || true
      fail "agent exited before /healthz responded"
    fi
  done

  # /healthz is up well before the docker-events subscription is live
  # (cold eBPF load + recovery of any existing managed containers can
  # add ~300-500ms between healthz-ready and event-stream-subscribed).
  # Cases that `docker run` immediately after this returns race the
  # event stream and miss the new container — observed flake on the
  # scope_label case when an unrelated managed=true container was
  # already running at agent start. Wait for the explicit marker
  # logged just before the agent enters its event loop.
  n=0
  until grep -q '"starting container event stream"' "$AGENT_LOG" 2>/dev/null; do
    sleep 0.1
    n=$((n+1))
    if (( n > 100 )); then
      log "agent /healthz up but event stream never subscribed; tail of log:"
      tail -n 40 "$AGENT_LOG" >&2 || true
      fail "agent event stream timeout"
    fi
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
      log "agent died after /healthz but before event stream subscribed; full log:"
      cat "$AGENT_LOG" >&2 || true
      fail "agent exited before event stream subscribed"
    fi
  done

  log "agent ready (pid=$AGENT_PID)"
}

stop_agent() {
  if [[ -n "${AGENT_PID:-}" ]] && kill -0 "$AGENT_PID" 2>/dev/null; then
    kill -TERM "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  AGENT_PID=
}

cleanup() {
  stop_agent || true
  if [[ "$KEEP_LOGS" == "0" ]]; then
    rm -rf "$WORK"
  else
    log "preserved sandbox at $WORK"
  fi
}
trap cleanup EXIT

write_rules() {
  local path="$1"
  shift
  cat >"$path" <<EOF
$@
EOF
}

metric_value() {
  local name="$1"
  curl -fsS "http://127.0.0.1:$METRICS_PORT/metrics" \
    | awk -v n="$name" '$1 ~ n && !/^#/ { sum += $NF } END { print sum+0 }'
}

# Wait up to $2 seconds for $1 evaluated as a shell expression to return
# 0. Used to bridge the gap between an event happening and the agent
# updating its sinks/metrics.
wait_for() {
  local cond="$1" timeout="${2:-10}"
  local end=$(( $(date +%s) + timeout ))
  until eval "$cond"; do
    if (( $(date +%s) > end )); then
      return 1
    fi
    sleep 0.2
  done
}

# ---------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------

# 1. Allow + block enforcement: a default-block scope with a single allow
#    rule for github.com. Curl github.com → succeeds; curl httpbin.org
#    → blocked by leitwacht's DNS proxy; both events show up in the NDJSON
#    stream and the Prometheus counter increments.
case_allow_block() {
  local sandbox="$WORK/allow_block"
  mkdir -p "$sandbox"

  local rules="$sandbox/rules.yaml"
  write_rules "$rules" 'schema_version: 1
scopes:
  - name: default
    default_action: block
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow
          ports: [443]
        - pattern: "*.github.com"
          pattern_type: wildcard
          action: allow
          ports: [443]'

  start_agent "$rules" "$sandbox"

  local cname="leitwacht-e2e-allow-$$"
  docker rm -f "$cname" >/dev/null 2>&1 || true

  log "running curl in test container (allowed: github.com)"
  if ! docker run --rm --name "$cname" --entrypoint sh \
        -e CI_PROJECT_PATH=team/app -e CI_JOB_ID=42 -e CI_JOB_NAME=build \
        -e FF_NETWORK_PER_BUILD=true \
        --label com.gitlab.gitlab-runner.managed=true \
        curlimages/curl:8.5.0 \
        -c "sleep ${ATTACH_DELAY} && curl --max-time 15 -fsSI https://github.com/ >/dev/null"; then
    fail "expected curl github.com to succeed under allow rule"
  fi

  log "running curl in test container (denied: httpbin.org)"
  if docker run --rm --name "$cname-deny" --entrypoint sh \
        -e CI_PROJECT_PATH=team/app -e CI_JOB_ID=43 -e CI_JOB_NAME=build \
        -e FF_NETWORK_PER_BUILD=true \
        --label com.gitlab.gitlab-runner.managed=true \
        curlimages/curl:8.5.0 \
        -c "sleep ${ATTACH_DELAY} && curl --max-time 10 -fsSI https://httpbin.org/ >/dev/null" 2>&1; then
    fail "curl httpbin.org should have been blocked"
  fi

  log "waiting for violation_total counter to advance"
  if ! wait_for '[[ "$(metric_value leitwacht_ce_violations_total)" -ge 1 ]]' 15; then
    log "metrics:"; curl -fsS "http://127.0.0.1:$METRICS_PORT/metrics" | grep leitwacht_ce_ >&2 || true
    fail "violations_total never incremented"
  fi

  log "checking NDJSON for violation_report on team/app"
  if ! grep -F '"type":"violation_report"' "$AGENT_LOG" \
       | grep -F '"project_path":"team/app"' \
       | grep -F '"hostname":"e2e-host"' >/dev/null; then
    log "agent log tail:"; tail -n 50 "$AGENT_LOG" >&2 || true
    fail "no NDJSON violation_report for team/app"
  fi

  ok "case_allow_block"
  stop_agent
}

# 2. Hot reload: start with default_action=allow, edit rules to flip the
#    catch-all to block, verify the next denied curl is actually denied.
case_hot_reload() {
  local sandbox="$WORK/hot_reload"
  mkdir -p "$sandbox"
  local rules="$sandbox/rules.yaml"

  write_rules "$rules" 'schema_version: 1
scopes:
  - name: default
    default_action: allow
    rule_sets:
      "":
        - pattern: example.com
          pattern_type: domain
          action: allow
          ports: [443]'

  start_agent "$rules" "$sandbox"

  log "v1 (allow-by-default): curl httpbin.org should succeed"
  if ! docker run --rm --entrypoint sh \
        -e CI_PROJECT_PATH=team/hr -e CI_JOB_ID=1 -e FF_NETWORK_PER_BUILD=true \
        --label com.gitlab.gitlab-runner.managed=true \
        curlimages/curl:8.5.0 \
        -c "sleep ${ATTACH_DELAY} && curl --max-time 15 -fsSI https://httpbin.org/ >/dev/null"; then
    fail "v1: curl should have succeeded under allow-by-default"
  fi

  log "rewriting rules to default_action: block"
  write_rules "$rules" 'schema_version: 1
scopes:
  - name: default
    default_action: block
    rule_sets:
      "":
        - pattern: example.com
          pattern_type: domain
          action: allow
          ports: [443]'

  # Wait for the agent to log a "rules reloaded" line (debounce + parse + swap).
  if ! wait_for 'grep -q "rules reloaded" "$AGENT_LOG"' 10; then
    log "no reload entry in agent log; tail:"; tail -n 50 "$AGENT_LOG" >&2 || true
    fail "agent did not pick up rules.yaml change"
  fi

  log "v2 (default block): curl httpbin.org should be blocked"
  if docker run --rm --entrypoint sh \
        -e CI_PROJECT_PATH=team/hr -e CI_JOB_ID=2 -e FF_NETWORK_PER_BUILD=true \
        --label com.gitlab.gitlab-runner.managed=true \
        curlimages/curl:8.5.0 \
        -c "sleep ${ATTACH_DELAY} && curl --max-time 10 -fsSI https://httpbin.org/ >/dev/null" 2>&1; then
    fail "v2: curl should have been blocked after reload"
  fi

  ok "case_hot_reload"
  stop_agent
}

# 3. Scope label: two scopes (default = block, trusted = allow). Container
#    with leitwacht.eu/scope=trusted should bypass the catch-all block.
case_scope_label() {
  local sandbox="$WORK/scope_label"
  mkdir -p "$sandbox"
  local rules="$sandbox/rules.yaml"

  write_rules "$rules" 'schema_version: 1
scopes:
  - name: default
    default_action: block
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow
          ports: [443]
  - name: trusted
    default_action: allow
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow
          ports: [443]'

  start_agent "$rules" "$sandbox"

  log "default scope: curl httpbin.org should be blocked"
  if docker run --rm --entrypoint sh \
        -e CI_PROJECT_PATH=team/strict -e CI_JOB_ID=10 -e FF_NETWORK_PER_BUILD=true \
        --label com.gitlab.gitlab-runner.managed=true \
        curlimages/curl:8.5.0 \
        -c "sleep ${ATTACH_DELAY} && curl --max-time 10 -fsSI https://httpbin.org/ >/dev/null" 2>&1; then
    fail "default scope: curl should have been blocked"
  fi

  log "trusted scope (via label): curl httpbin.org should pass"
  if ! docker run --rm --entrypoint sh \
        -e CI_PROJECT_PATH=team/loose -e CI_JOB_ID=11 -e FF_NETWORK_PER_BUILD=true \
        --label com.gitlab.gitlab-runner.managed=true \
        --label leitwacht.eu/scope=trusted \
        curlimages/curl:8.5.0 \
        -c "sleep ${ATTACH_DELAY} && curl --max-time 15 -fsSI https://httpbin.org/ >/dev/null"; then
    fail "trusted scope: curl should have succeeded"
  fi

  ok "case_scope_label"
  stop_agent
}

# 4. Webhook fan-out: agent posts violation reports to an httptest-style
#    listener (here we use `nc -l` to capture one POST and check for the
#    expected JSON envelope).
case_webhook_sink() {
  local sandbox="$WORK/webhook_sink"
  mkdir -p "$sandbox"
  local rules="$sandbox/rules.yaml"
  local hook_port=18080

  write_rules "$rules" 'schema_version: 1
scopes:
  - name: default
    default_action: block
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow
          ports: [443]'

  # Defensive: a prior failed run may have left a python listener
  # bound to this port (the test exits before reaching the kill at
  # the bottom on agent-startup failures). fuser -k is idempotent.
  fuser -k "${hook_port}/tcp" 2>/dev/null || true
  sleep 0.1

  log "launching minimal webhook listener on :$hook_port"
  ( python3 -c "
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers['Content-Length'])
        body=self.rfile.read(n).decode()
        sys.stdout.write(body+'\n'); sys.stdout.flush()
        self.send_response(202); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1',$hook_port),H).serve_forever()
" >"$sandbox/hook.log" 2>&1 ) &
  local hook_pid=$!
  sleep 0.3

  # Env vars on a function-call line apply to the function execution,
  # which then propagates them to the backgrounded `"$BIN" &` agent
  # process — this is the trick that lets per-case env override the
  # shared start_agent helper without restructuring it.
  LEITWACHT_CE_WEBHOOK_URL="http://127.0.0.1:$hook_port/" \
  LEITWACHT_CE_WEBHOOK_AUTH="Bearer e2e-token" \
    start_agent "$rules" "$sandbox"

  docker run --rm --entrypoint sh \
    -e CI_PROJECT_PATH=team/wh -e CI_JOB_ID=99 -e FF_NETWORK_PER_BUILD=true \
    --label com.gitlab.gitlab-runner.managed=true \
    curlimages/curl:8.5.0 \
    -c "sleep ${ATTACH_DELAY} && curl --max-time 10 -fsSI https://httpbin.org/ >/dev/null" 2>&1 || true

  if ! wait_for 'grep -F violation_report "$sandbox/hook.log" >/dev/null' 15; then
    log "no webhook delivery; hook.log:"; cat "$sandbox/hook.log" >&2 || true
    fail "webhook listener never received a violation_report"
  fi

  ok "case_webhook_sink"
  stop_agent
  kill "$hook_pid" 2>/dev/null || true
}

# 5. Env-name capture: when LEITWACHT_CE_RECORD_ENV_NAMES=true the
#    agent attaches the offending PID's env-var NAMES (never values)
#    to each violation report. We seed a unique marker var on the test
#    container, generate a violation, and assert the NDJSON envelope
#    carries the marker name in env_names — but never its value.
case_env_names() {
  local sandbox="$WORK/env_names"
  mkdir -p "$sandbox"
  local rules="$sandbox/rules.yaml"

  write_rules "$rules" 'schema_version: 1
scopes:
  - name: default
    default_action: block
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow
          ports: [443]'

  # Marker name + value. The value contains a sentinel string that
  # must NEVER appear in the NDJSON output — that would mean the agent
  # leaked env values, breaking the names-only contract.
  local marker_name="LEITWACHT_E2E_MARKER_$$"
  local marker_secret="never-in-ndjson-${RANDOM}${RANDOM}"

  LEITWACHT_CE_RECORD_ENV_NAMES=true \
    start_agent "$rules" "$sandbox"

  log "running curl with marker env (denied: httpbin.org)"
  docker run --rm --entrypoint sh \
        -e CI_PROJECT_PATH=team/env -e CI_JOB_ID=99 \
        -e FF_NETWORK_PER_BUILD=true \
        -e "${marker_name}=${marker_secret}" \
        --label com.gitlab.gitlab-runner.managed=true \
        curlimages/curl:8.5.0 \
        -c "sleep ${ATTACH_DELAY} && curl --max-time 10 -fsSI https://httpbin.org/ >/dev/null" 2>&1 || true

  log "waiting for violation_report carrying env_names"
  if ! wait_for "grep -F '\"env_names\"' \"\$AGENT_LOG\" >/dev/null" 15; then
    log "agent.log tail:"; tail -50 "$AGENT_LOG" >&2
    fail "no violation_report contained env_names"
  fi

  log "asserting marker NAME is present in env_names"
  if ! grep -F "$marker_name" "$AGENT_LOG" >/dev/null; then
    fail "marker name $marker_name not found in NDJSON env_names"
  fi

  log "asserting marker VALUE is NOT in NDJSON (names-only contract)"
  if grep -F "$marker_secret" "$AGENT_LOG" >/dev/null; then
    fail "SECURITY: marker value leaked into NDJSON output"
  fi

  ok "case_env_names"
  stop_agent
}

# 7. Bare-IP exfil bypass: an attacker that skips DNS and connects
#    directly to a hardcoded IP must still be blocked by the eBPF
#    default-deny on the egress cgroup. This is the failure mode where
#    domain-level rules alone wouldn't help — the only thing standing
#    in the way is "if the IP isn't in the allow map, drop." We use
#    1.1.1.1:80 (Cloudflare's HTTP test endpoint) as a stable target;
#    nothing in the rules allows it.
case_bare_ip_blocked() {
  local sandbox="$WORK/bare_ip"
  mkdir -p "$sandbox"
  local rules="$sandbox/rules.yaml"

  # Default-block scope; allow one unrelated domain so the DNS proxy
  # has *something* to allow (proves the block isn't because the proxy
  # rejected literally everything).
  write_rules "$rules" 'schema_version: 1
scopes:
  - name: default
    default_action: block
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow
          ports: [443]'

  start_agent "$rules" "$sandbox"

  log "running curl to a hardcoded IP (no DNS resolution): http://1.1.1.1/"
  # --max-time short so the dropped SYN times out fast; we expect
  # non-zero exit (curl: 28 = timeout, 7 = couldn't connect — either
  # is acceptable proof the packet was dropped).
  if docker run --rm --entrypoint sh \
        -e CI_PROJECT_PATH=team/bare -e CI_JOB_ID=11 \
        -e FF_NETWORK_PER_BUILD=true \
        --label com.gitlab.gitlab-runner.managed=true \
        curlimages/curl:8.5.0 \
        -c "sleep ${ATTACH_DELAY} && curl --max-time 5 -fsSI http://1.1.1.1/ >/dev/null" 2>&1; then
    fail "curl http://1.1.1.1/ should have been blocked at packet layer (default-deny)"
  fi

  log "asserting NO DNS activity recorded for the bare IP path"
  # Confirms the path under test: this packet was NOT preceded by a
  # DNS query through our proxy. If we see DNS activity tied to this
  # job, the test is exercising the wrong codepath.
  if grep -F '"project_path":"team/bare"' "$AGENT_LOG" | grep -F '"dns_activity"' | grep -F '1.1.1.1' >/dev/null; then
    fail "unexpected DNS activity for 1.1.1.1 — the bare-IP path should have no preceding query"
  fi

  log "waiting for packet-layer violation against 1.1.1.1"
  if ! wait_for "grep -F '\"ip\":\"1.1.1.1\"' \"\$AGENT_LOG\" >/dev/null" 15; then
    log "agent.log tail:"; tail -50 "$AGENT_LOG" >&2
    fail "no violation recorded for the bare-IP egress to 1.1.1.1"
  fi

  log "asserting violation action is packet-layer (not dns_*)"
  # The violation for 1.1.1.1 should be packet_dropped (or sinkhole_hit
  # if 1.1.1.1 ever ended up in the deny map, which it shouldn't here).
  # Either way it should NOT be a dns_* action — those imply we
  # intercepted via DNS proxy, which the test is specifically not
  # exercising.
  if grep -F '"ip":"1.1.1.1"' "$AGENT_LOG" | grep -F '"action":"dns_' >/dev/null; then
    fail "1.1.1.1 violation tagged with dns_* action; expected packet-layer drop"
  fi

  ok "case_bare_ip_blocked"
  stop_agent
}

# 6. DNS qtype reporting: a TXT query against a non-allowed domain should
#    surface in the report with query_type:"TXT" — DNSCat-style exfil
#    tools rely on TXT/NULL/MX abuse, so qtype is the highest-value
#    forensic signal we capture for tunnel detection.
case_dns_qtype() {
  local sandbox="$WORK/dns_qtype"
  mkdir -p "$sandbox"
  local rules="$sandbox/rules.yaml"

  write_rules "$rules" 'schema_version: 1
scopes:
  - name: default
    default_action: block
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow
          ports: [443]'

  start_agent "$rules" "$sandbox"

  log "running dig TXT against denied domain"
  docker run --rm --entrypoint sh \
        -e CI_PROJECT_PATH=team/qtype -e CI_JOB_ID=77 \
        -e FF_NETWORK_PER_BUILD=true \
        --label com.gitlab.gitlab-runner.managed=true \
        curlimages/curl:8.5.0 \
        -c "sleep ${ATTACH_DELAY} && nslookup -type=TXT c2-test.example.invalid 127.0.0.11 2>&1 || true" 2>&1 || true

  log "waiting for violation_report carrying query_type"
  if ! wait_for "grep -F '\"query_type\":\"TXT\"' \"\$AGENT_LOG\" >/dev/null" 15; then
    log "agent.log tail:"; tail -50 "$AGENT_LOG" >&2
    fail "no DNS report contained query_type:TXT"
  fi

  ok "case_dns_qtype"
  stop_agent
}

# ---------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------

main() {
  require curl jq docker go python3
  if [[ "$EUID" -ne 0 ]]; then
    fail "must run as root (eBPF + nftables); try: sudo -E $0"
  fi

  build_agent

  local cases=(allow_block hot_reload scope_label webhook_sink env_names dns_qtype bare_ip_blocked)
  if (( $# > 0 )); then
    cases=("$@")
  fi

  for c in "${cases[@]}"; do
    log "─── case_${c} ────────────────────────────────────────────"
    "case_${c}"
  done

  printf '\n\033[32m== all e2e cases passed ==\033[0m\n'
}

main "$@"
