#!/usr/bin/env bash
set -euo pipefail

CANONICAL_REPO="${1:-${CANONICAL_REPO:-$HOME/dev/orxaq}}"
SCRATCH_ROOT="${SCRATCH_ROOT:-$HOME/dev/cass-scratch}"
RUNTIME_ROOT="${RUNTIME_ROOT:-/Library/Application Support/com.orxaq.cass}"
POLICY_PATH="${POLICY_PATH:-$RUNTIME_ROOT/policies/active-policy.signed.json}"
SCRATCH_NAME="${SCRATCH_NAME:-$(basename "$CANONICAL_REPO")-$(date +%Y%m%d-%H%M%S)-$$}"
SCRATCH_REPO="${SCRATCH_REPO:-$SCRATCH_ROOT/$SCRATCH_NAME}"
BRANCH_NAME="${BRANCH_NAME:-cass/$(date +%Y%m%d-%H%M%S)}"

mkdir -p "$SCRATCH_ROOT"

if [[ -e "$SCRATCH_REPO" ]]; then
  echo "scratch repo already exists: $SCRATCH_REPO" >&2
  exit 1
fi

git clone --quiet "$CANONICAL_REPO" "$SCRATCH_REPO"
git -C "$SCRATCH_REPO" checkout -q -b "$BRANCH_NAME"

python3 - <<PY
import os
import shutil
import subprocess
from pathlib import Path

canonical = Path("$CANONICAL_REPO").resolve()
scratch = Path("$SCRATCH_REPO").resolve()

raw = subprocess.check_output(
    ["git", "-C", str(canonical), "status", "--porcelain", "-z", "--untracked-files=all"],
    text=False,
)

entries = [entry.decode("utf-8", "replace") for entry in raw.split(b"\0") if entry]
i = 0
while i < len(entries):
    entry = entries[i]
    status = entry[:2]
    path = entry[3:]
    if status.startswith("R") or status.startswith("C"):
        i += 1
        path = entries[i]

    source = canonical / path
    destination = scratch / path

    if source.exists() or source.is_symlink():
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir() and not source.is_symlink():
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(source, destination, symlinks=True)
        elif source.is_symlink():
            if destination.exists() or destination.is_symlink():
                if destination.is_dir() and not destination.is_symlink():
                    shutil.rmtree(destination)
                else:
                    destination.unlink()
            target = os.readlink(source)
            os.symlink(target, destination)
        else:
            shutil.copy2(source, destination)
    else:
        if destination.exists() or destination.is_symlink():
            if destination.is_dir() and not destination.is_symlink():
                shutil.rmtree(destination)
            else:
                destination.unlink()

    i += 1
PY

if [[ -d "$CANONICAL_REPO/.venv" && ! -e "$SCRATCH_REPO/.venv" ]]; then
  ln -s "$CANONICAL_REPO/.venv" "$SCRATCH_REPO/.venv"
fi

mkdir -p "$SCRATCH_REPO/.cass"

python3 - <<PY
import json
from pathlib import Path

metadata = {
    "branch_name": "$BRANCH_NAME",
    "canonical_repo": Path("$CANONICAL_REPO").resolve().as_posix(),
    "scratch_repo": Path("$SCRATCH_REPO").resolve().as_posix(),
    "runtime_root": Path("$RUNTIME_ROOT").resolve().as_posix(),
    "policy_path": Path("$POLICY_PATH").resolve().as_posix(),
}

Path("$SCRATCH_REPO/.cass/scratch-session.json").write_text(
    json.dumps(metadata, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

printf 'scratch_repo=%s\n' "$SCRATCH_REPO"
printf 'canonical_repo=%s\n' "$CANONICAL_REPO"
printf 'branch_name=%s\n' "$BRANCH_NAME"
printf 'next=cd %q && claude\n' "$SCRATCH_REPO"
