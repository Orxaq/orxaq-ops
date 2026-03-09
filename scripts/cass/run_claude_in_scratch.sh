#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CREATE_SCRIPT="$SCRIPT_DIR/create_scratch_clone.sh"

CANONICAL_REPO="${1:-${CANONICAL_REPO:-$HOME/dev/orxaq}}"
shift $(( $# > 0 ? 1 : 0 ))

if ! command -v claude >/dev/null 2>&1; then
  echo "claude command not found" >&2
  exit 1
fi

OUTPUT="$("$CREATE_SCRIPT" "$CANONICAL_REPO")"
SCRATCH_REPO=$(printf '%s\n' "$OUTPUT" | awk -F= '/^scratch_repo=/{print $2}')

printf '%s\n' "$OUTPUT"
cd "$SCRATCH_REPO"
exec claude "$@"
