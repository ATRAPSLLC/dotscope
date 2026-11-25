#!/bin/bash
# Generates dotscope's test samples on Linux, in Docker, with no Windows host.
#
#   ./build.sh [--force] <family>...      e.g. ./build.sh confuserex variants oracle
#   ./build.sh --all                      every family, then the oracle
#
# The image (see `Dockerfile`) is built on first use and whenever the Dockerfile is newer
# than it. `tests/samples` is mounted read-write at /samples; downloads are cached in a
# named volume so a rerun does not fetch them again. See `generate.sh` for the families.

set -euo pipefail

cd "$(dirname "$0")"

readonly IMAGE="dotscope-samples:wine"

# Rebuilt when its Dockerfile is newer than it.
ensure_image() {
    local created
    created="$(docker image inspect -f '{{.Created}}' "$IMAGE" 2>/dev/null || true)"
    if [ -z "$created" ] || [ "$(date -d "$created" +%s)" -lt "$(stat -c %Y Dockerfile)" ]; then
        docker build -t "$IMAGE" .
    fi
}

ensure_image

if [ "${1:-}" = "--all" ]; then
    set -- confuserex bitmono obfuscar jiejie variants sections debug pdb winmd oracle
fi
[ "$#" -gt 0 ] || { echo "usage: build.sh [--force] <family>... | --all" >&2; exit 2; }

# The container runs as root, since Wine refuses a prefix owned by another user;
# `generate.sh` hands every file it creates to the invoking user before it exits.
docker run --rm \
    -e OWNER="$(id -u):$(id -g)" \
    -v "$(realpath ..):/samples" \
    -v dotscope-samples-cache:/cache \
    "$IMAGE" bash /samples/factory/generate.sh "$@" \
    2> >(grep -v XDG_RUNTIME_DIR >&2)
