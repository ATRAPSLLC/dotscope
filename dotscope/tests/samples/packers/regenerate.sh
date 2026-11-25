#!/usr/bin/env bash
#
# Regenerate the .NET Reactor test samples via a Windows SSH host.
#
# .NET Reactor is commercial and runs only on a licensed Windows install, so its samples
# are made remotely: this script copies the shared TestApp source and the generation
# script to a Windows machine, runs netreactor/generate.ps1 there, and copies the
# resulting .exe files back.
#
# Every other protector (ConfuserEx, BitMono, Obfuscar, JIEJIE.NET) is generated on Linux
# by `../factory/build.sh`, which runs each as its .NET Framework build under Wine and checks
# every sample against the CLR. Their former generate.ps1 scripts ran BitMono, Obfuscar and
# JIEJIE on .NET (Core), which binds the code they inject to that runtime, so the samples
# did not load on the .NET Framework they target.
#
# Environment variables (required):
#   WINDOWS_HOST  - SSH host string, e.g. "user@host" or "user@host -p 2222"
#   REMOTE_DIR    - Working directory on the Windows host, e.g. "C:/Users/you/dotscope_samples"
#
# Usage:
#   export WINDOWS_HOST="user@host -p 22"
#   export REMOTE_DIR="C:/Users/you/dotscope_samples"
#   ./regenerate.sh                        # Regenerate the .NET Reactor samples
#
# Prerequisites:
#   - SSH key-based auth configured for the Windows host
#   - Windows host has: .NET SDK 8.0+, .NET Framework 4.8 SDK, a licensed .NET Reactor

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[regenerate]${NC} $*"; }
ok()   { echo -e "${GREEN}[regenerate]${NC} $*"; }
warn() { echo -e "${YELLOW}[regenerate]${NC} $*"; }
err()  { echo -e "${RED}[regenerate]${NC} $*" >&2; }

# SSH connection (required env vars)
if [ -z "${WINDOWS_HOST:-}" ]; then
    err "WINDOWS_HOST is not set. Export it first, e.g.:"
    err "  export WINDOWS_HOST='user@host -p 22'"
    exit 1
fi
if [ -z "${REMOTE_DIR:-}" ]; then
    err "REMOTE_DIR is not set. Export it first, e.g.:"
    err "  export REMOTE_DIR='C:/Users/you/dotscope_samples'"
    exit 1
fi

# Local paths
TESTAPP_DIR="$SCRIPT_DIR/source/TestApp"
NETREACTOR_SCRIPT="$SCRIPT_DIR/netreactor/generate.ps1"
NETREACTOR_SAMPLES="$SCRIPT_DIR/netreactor/7.5.0"

# Build SSH command array — handles port and user@host
build_ssh_args() {
    read -ra SSH_PARTS <<< "$WINDOWS_HOST"
    SSH_ARGS=("${SSH_PARTS[@]}")
}

# Run a command on the remote host via PowerShell (Windows SSH defaults to CMD)
run_ssh() {
    ssh "${SSH_ARGS[@]}" "powershell -NoProfile -Command \"$*\""
}

# Run a raw command (no PowerShell wrapper) for simple cases
run_ssh_raw() {
    ssh "${SSH_ARGS[@]}" "$@"
}

# Extract host and port from SSH_ARGS once for scp usage
parse_scp_args() {
    SCP_HOST=""
    SCP_PORT_ARGS=()
    local i=0
    while [ $i -lt ${#SSH_ARGS[@]} ]; do
        case "${SSH_ARGS[$i]}" in
            -p)
                SCP_PORT_ARGS=(-P "${SSH_ARGS[$((i+1))]}")
                i=$((i+2))
                ;;
            *)
                SCP_HOST="${SSH_ARGS[$i]}"
                i=$((i+1))
                ;;
        esac
    done
}

run_scp_to() {
    local src="$1" dst="$2"
    scp "${SCP_PORT_ARGS[@]}" -r "$src" "${SCP_HOST}:${dst}"
}

# Download all .exe files from a remote directory
download_exes() {
    local remote_dir="$1" local_dir="$2"
    # List remote .exe files, then download each one
    local files
    files=$(run_ssh "Get-ChildItem -Path '${remote_dir}' -Filter '*.exe' | ForEach-Object { \$_.Name }" 2>/dev/null | tr -d '\r')
    if [ -z "$files" ]; then
        warn "No .exe files found in remote directory $remote_dir"
        return 1
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        scp "${SCP_PORT_ARGS[@]}" "${SCP_HOST}:${remote_dir}/${f}" "${local_dir}/"
    done <<< "$files"
}

# Determine which obfuscators to regenerate
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS=(netreactor)
fi

build_ssh_args
parse_scp_args

# ── Step 1: Verify SSH connectivity ──────────────────────────────────────────
log "Testing SSH connection to $WINDOWS_HOST..."
if ! run_ssh_raw "echo ok" >/dev/null 2>&1; then
    err "Cannot connect to Windows host. Check WINDOWS_HOST env var and SSH keys."
    exit 1
fi
ok "SSH connection verified."

# ── Step 2: Prepare remote working directory ─────────────────────────────────
log "Creating remote directory $REMOTE_DIR..."
run_ssh "New-Item -ItemType Directory -Path '${REMOTE_DIR}/TestApp/Resources' -Force | Out-Null; \
         New-Item -ItemType Directory -Path '${REMOTE_DIR}/output' -Force | Out-Null"

# ── Step 3: Upload TestApp source ────────────────────────────────────────────
log "Uploading TestApp source..."
run_scp_to "$TESTAPP_DIR/Program.cs" "$REMOTE_DIR/TestApp/"
run_scp_to "$TESTAPP_DIR/TestApp.csproj" "$REMOTE_DIR/TestApp/"
run_scp_to "$TESTAPP_DIR/Resources/greeting.txt" "$REMOTE_DIR/TestApp/Resources/"
run_scp_to "$TESTAPP_DIR/Resources/data.bin" "$REMOTE_DIR/TestApp/Resources/"
ok "TestApp source uploaded."

# ── Step 4: Run each obfuscator ──────────────────────────────────────────────

regenerate_netreactor() {
    log "=== .NET Reactor ==="

    # Upload generation script (no config files, flags are inline in the script)
    run_ssh "New-Item -ItemType Directory -Path '${REMOTE_DIR}/netreactor' -Force | Out-Null"
    run_scp_to "$NETREACTOR_SCRIPT" "$REMOTE_DIR/netreactor/"

    # Run generation
    log "Running .NET Reactor generate.ps1..."
    run_ssh "& '${REMOTE_DIR}/netreactor/generate.ps1' \
        -TestAppPath '${REMOTE_DIR}/TestApp/TestApp.csproj' \
        -OutputDir '${REMOTE_DIR}/output/netreactor'"

    # Download results
    log "Downloading .NET Reactor samples..."
    download_exes "$REMOTE_DIR/output/netreactor" "$NETREACTOR_SAMPLES"

    local count
    count=$(ls "$NETREACTOR_SAMPLES"/*.exe 2>/dev/null | wc -l | tr -d ' ')
    ok ".NET Reactor: $count samples in place."
}

for target in "${TARGETS[@]}"; do
    case "$target" in
        netreactor)  regenerate_netreactor ;;
        *)
            err "Unknown target: $target (valid: netreactor; the others are made by ../factory/build.sh)"
            exit 1
            ;;
    esac
done

# ── Step 5: Summary ──────────────────────────────────────────────────────────
echo ""
log "════════════════════════════════════════════════════════════════"
ok "Regeneration complete for: ${TARGETS[*]}"
log ""
log "Verify with:"
for target in "${TARGETS[@]}"; do
    log "  cargo test --profile ci-test --test $target"
done
log "════════════════════════════════════════════════════════════════"
