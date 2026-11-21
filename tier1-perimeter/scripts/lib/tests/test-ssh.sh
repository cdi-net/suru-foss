#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — test-ssh.sh
# Hermetic tests for scripts/lib/ssh.sh: the argv and stdin each wrapper hands
# to ssh, the StrictHostKeyChecking contract, the optional ssh_exec_heredoc
# interpreter, and DRY_RUN. `ssh` is a PATH stub that records its arguments and
# stdin; no network, no router.
# Run: bash tier1-perimeter/scripts/lib/tests/test-ssh.sh
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
# shellcheck source=../../../../lib/bash/test-harness.sh
source "${REPO_ROOT}/lib/bash/test-harness.sh"
# shellcheck source=../log.sh
source "${SCRIPT_DIR}/../log.sh"
# shellcheck source=../ssh.sh
source "${SCRIPT_DIR}/../ssh.sh"

WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT
mkdir -p "${WORK}/bin"
: > "${WORK}/key"

cat > "${WORK}/bin/ssh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "${SSH_TEST_WORK}/args.log"
cat > "${SSH_TEST_WORK}/stdin.log"
: > "${SSH_TEST_WORK}/called"
STUB
chmod +x "${WORK}/bin/ssh"
export SSH_TEST_WORK="${WORK}"
export PATH="${WORK}/bin:${PATH}"

export ROUTER_HOST=router.test
export ROUTER_SSH_USER=deploy
export ROUTER_SSH_KEY="${WORK}/key"
unset SSH_STRICT_HOST_KEY_CHECKING DRY_RUN || true

ARGS="${WORK}/args.log"
STDIN="${WORK}/stdin.log"
reset() { rm -f -- "${ARGS}" "${STDIN}" "${WORK}/called"; }
last_arg() { tail -n 1 "${ARGS}"; }

echo "== ssh_exec =="
reset
ssh_exec 'uptime' < /dev/null
assert_eq "ssh_exec: last arg is sh -c \"uptime\"" 'sh -c "uptime"' "$(last_arg)"
assert_eq "ssh_exec: target precedes the command" "deploy@router.test" "$(tail -n 2 "${ARGS}" | head -n 1)"

echo "== ssh_exec_heredoc =="
reset
ssh_exec_heredoc $'a\nb'
assert_eq "heredoc default: last arg is bash -s" "bash -s" "$(last_arg)"
assert_eq "heredoc default: stdin is the script plus one newline" $'a\nb' "$(cat "${STDIN}")"
assert_eq "heredoc default: stdin has exactly 2 lines" "2" "$(wc -l < "${STDIN}" | tr -d ' ')"

reset
ssh_exec_heredoc 'x' 'sudo sh'
assert_eq "heredoc interpreter: last arg is the single token 'sudo sh'" "sudo sh" "$(last_arg)"
assert_eq "heredoc interpreter: target precedes it" "deploy@router.test" "$(tail -n 2 "${ARGS}" | head -n 1)"

echo "== StrictHostKeyChecking contract =="
reset
ssh_exec_heredoc 'x'
if grep -qxF 'StrictHostKeyChecking=yes' "${ARGS}"; then _pass "strict unset: defaults to yes"; else _fail "strict unset: defaults to yes"; fi
if grep -qxF 'BatchMode=yes' "${ARGS}" && grep -qxF 'ConnectTimeout=15' "${ARGS}"; then _pass "options: BatchMode=yes and ConnectTimeout=15"; else _fail "options: BatchMode=yes and ConnectTimeout=15"; fi
reset
SSH_STRICT_HOST_KEY_CHECKING=accept-new ssh_exec_heredoc 'x'
if grep -qxF 'StrictHostKeyChecking=accept-new' "${ARGS}"; then _pass "strict accept-new: passed through"; else _fail "strict accept-new: passed through"; fi

echo "== DRY_RUN =="
reset
DRY_RUN=true ssh_exec_heredoc 'echo hi' 'sudo sh' > "${WORK}/dry.txt"
if [[ -e "${WORK}/called" ]]; then _fail "dry-run: ssh is not called"; else _pass "dry-run: ssh is not called"; fi
if grep -q 'DRY-RUN' "${WORK}/dry.txt" && grep -qF 'sudo sh' "${WORK}/dry.txt"; then _pass "dry-run: line names the interpreter"; else _fail "dry-run: line names the interpreter"; fi
if grep -qF 'echo hi' "${WORK}/dry.txt"; then _pass "dry-run: script is printed"; else _fail "dry-run: script is printed"; fi

echo "== connection reuse =="
reset
ssh_exec 'uptime' < /dev/null
if grep -q '^Control' "${ARGS}"; then _fail "reuse off by default: no Control* options"; else _pass "reuse off by default: no Control* options"; fi

ssh_mux_enable
mux_dir="${_SSH_MUX_DIR}"
if [[ -n "${mux_dir}" && -d "${mux_dir}" ]]; then _pass "enable: control directory created"; else _fail "enable: control directory created"; fi
assert_eq "enable: control directory is 0700" "700" "$(stat -c '%a' "${mux_dir}" 2>/dev/null || stat -f '%Lp' "${mux_dir}")"
# The socket path is <dir>/<40 hex %C> plus a temporary suffix ssh adds while
# binding; a Unix socket path is capped near 104 bytes (macOS).
if (( ${#mux_dir} + 1 + 40 + 17 < 104 )); then _pass "enable: socket path fits the Unix socket limit"; else _fail "enable: socket path fits the Unix socket limit (${#mux_dir})"; fi
reset
ssh_exec 'uptime' < /dev/null
if grep -qxF 'ControlMaster=auto' "${ARGS}" && grep -qxF "ControlPath=${mux_dir}/%C" "${ARGS}"; then _pass "enable: ssh_exec carries ControlMaster=auto and the per-run ControlPath"; else _fail "enable: ssh_exec carries ControlMaster=auto and the per-run ControlPath"; fi
if grep -qxF 'ControlPersist=120' "${ARGS}" && grep -qxF 'ServerAliveInterval=30' "${ARGS}" && grep -qxF 'ServerAliveCountMax=10' "${ARGS}"; then _pass "enable: ControlPersist 120 and the 30 s x 10 keepalive"; else _fail "enable: ControlPersist 120 and the 30 s x 10 keepalive"; fi
assert_eq "enable: target still precedes the command" "deploy@router.test" "$(tail -n 2 "${ARGS}" | head -n 1)"
ssh_mux_enable
assert_eq "enable: idempotent (same directory)" "${mux_dir}" "${_SSH_MUX_DIR}"
# shellcheck source=../ssh.sh
source "${SCRIPT_DIR}/../ssh.sh"
assert_eq "re-source keeps the live directory" "${mux_dir}" "${_SSH_MUX_DIR}"

reset
if command -v python3 > /dev/null 2>&1 \
   && python3 -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${mux_dir}/0123456789abcdef0123456789abcdef01234567"; then
  ssh_mux_close
  if grep -qxF -- '-O' "${ARGS}" && grep -qxF 'exit' "${ARGS}" \
     && grep -qxF "ControlPath=${mux_dir}/0123456789abcdef0123456789abcdef01234567" "${ARGS}"; then
    _pass "close: sends -O exit to the master socket"
  else
    _fail "close: sends -O exit to the master socket"
  fi
else
  ssh_mux_close
  echo "  [SKIP] close: sends -O exit to the master socket (no python3 to bind a Unix socket)"
fi
if [[ -d "${mux_dir}" ]]; then _fail "close: control directory removed"; else _pass "close: control directory removed"; fi
assert_eq "close: options cleared" "0" "${#SSH_MUX_OPTS[@]}"
reset
ssh_mux_close
if [[ -e "${WORK}/called" ]]; then _fail "close: no-op when reuse is off"; else _pass "close: no-op when reuse is off"; fi

SURU_SSH_MUX=false ssh_mux_enable
assert_eq "SURU_SSH_MUX=false: reuse stays off" "0" "${#SSH_MUX_OPTS[@]}"

test_summary
