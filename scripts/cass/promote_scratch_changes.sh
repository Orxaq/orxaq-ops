#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGE_DIR="$ROOT_DIR/tools/cass-kernel-gate"
BUILD_DIR="$PACKAGE_DIR/.build/arm64-apple-macosx/debug"
CASSCTL="${CASSCTL:-$BUILD_DIR/cassctl}"

SCRATCH_REPO="${1:-${SCRATCH_REPO:-$PWD}}"
METADATA_PATH="${METADATA_PATH:-$SCRATCH_REPO/.cass/scratch-session.json}"
RUNTIME_ROOT_OVERRIDE="${RUNTIME_ROOT:-}"
SIGNED_POLICY_OVERRIDE="${SIGNED_POLICY_PATH:-}"
DRY_RUN=0
FILES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --file)
      FILES+=("$2")
      shift 2
      ;;
    --runtime-root)
      RUNTIME_ROOT_OVERRIDE="$2"
      shift 2
      ;;
    --signed-policy)
      SIGNED_POLICY_OVERRIDE="$2"
      shift 2
      ;;
    *)
      if [[ "$1" == "$SCRATCH_REPO" ]]; then
        shift
      else
        FILES+=("$1")
        shift
      fi
      ;;
  esac
done

if [[ ! -f "$METADATA_PATH" ]]; then
  echo "missing scratch metadata: $METADATA_PATH" >&2
  exit 1
fi

META_RAW=$(python3 - <<PY
import json
from pathlib import Path
data = json.loads(Path("$METADATA_PATH").read_text(encoding="utf-8"))
print(data["canonical_repo"])
print(data["runtime_root"])
print(data["policy_path"])
PY
)

CANONICAL_REPO=$(printf '%s\n' "$META_RAW" | sed -n '1p')
DEFAULT_RUNTIME_ROOT=$(printf '%s\n' "$META_RAW" | sed -n '2p')
DEFAULT_POLICY_PATH=$(printf '%s\n' "$META_RAW" | sed -n '3p')

RUNTIME_ROOT="${RUNTIME_ROOT_OVERRIDE:-$DEFAULT_RUNTIME_ROOT}"
SIGNED_POLICY="${SIGNED_POLICY_OVERRIDE:-$DEFAULT_POLICY_PATH}"

if [[ ! -x "$CASSCTL" ]]; then
  swift build --package-path "$PACKAGE_DIR" >/dev/null
fi

if [[ ${#FILES[@]} -eq 0 ]]; then
  while IFS= read -r line; do
    [[ -n "$line" ]] && FILES+=("$line")
  done < <(
    cd "$SCRATCH_REPO"
    {
      git diff --name-only --diff-filter=ACMR HEAD
      git ls-files --others --exclude-standard
    } | awk 'NF' | sort -u
  )
fi

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "no changed files to promote"
  exit 0
fi

for rel_path in "${FILES[@]}"; do
  case "$rel_path" in
    .cass/*|.git/*|.git|.venv|.venv/*)
      continue
      ;;
  esac

  source_path="$SCRATCH_REPO/$rel_path"
  target_path="$CANONICAL_REPO/$rel_path"

  if [[ ! -f "$source_path" ]]; then
    echo "skip non-file: $rel_path" >&2
    continue
  fi

  cmd=(
    "$CASSCTL"
    promote
    --runtime-root "$RUNTIME_ROOT"
    --signed-policy "$SIGNED_POLICY"
    --source "$source_path"
    --target "$target_path"
  )
  if [[ "$DRY_RUN" == "1" ]]; then
    cmd+=(--dry-run)
  fi

  "${cmd[@]}"
done
