#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGE_DIR="$ROOT_DIR/tools/cass-kernel-gate"
BUILD_DIR="$PACKAGE_DIR/.build/arm64-apple-macosx/debug"
STATE_DIR="$ROOT_DIR/state/cass"

HOME_DIR="${HOME_DIR:-$HOME}"
REPO_DIR="${REPO_DIR:-$HOME/dev/orxaq}"
VERIFIER_PATH="${VERIFIER_PATH:-$REPO_DIR/.claude/hooks/cass_code_verify.sh}"
PROFILE="${PROFILE:-strict}"
MEMORY_CONTROL="${MEMORY_CONTROL:-disabled}"
RUNTIME_ROOT="${RUNTIME_ROOT:-/Library/Application Support/com.orxaq.cass}"

UNSIGNED_POLICY_PATH="${UNSIGNED_POLICY_PATH:-$STATE_DIR/claude-code-$PROFILE.policy.json}"
SIGNED_POLICY_PATH="${SIGNED_POLICY_PATH:-$STATE_DIR/claude-code-$PROFILE.policy.signed.json}"

mkdir -p "$STATE_DIR"

swift build --package-path "$PACKAGE_DIR"

"$BUILD_DIR/cass-policy" init-claude \
  --home "$HOME_DIR" \
  --repo "$REPO_DIR" \
  --verifier "$VERIFIER_PATH" \
  --profile "$PROFILE" \
  --memory-control "$MEMORY_CONTROL" \
  --output "$UNSIGNED_POLICY_PATH"

if [[ -n "${CASS_IDENTITY_COMMON_NAME:-}" ]]; then
  "$BUILD_DIR/cassctl" policy sign \
    --policy "$UNSIGNED_POLICY_PATH" \
    --output "$SIGNED_POLICY_PATH" \
    --identity-common-name "$CASS_IDENTITY_COMMON_NAME"

  "$BUILD_DIR/cassctl" install-policy \
    --signed-policy "$SIGNED_POLICY_PATH" \
    --runtime-root "$RUNTIME_ROOT"

  if [[ "${CASS_ACTIVATE:-0}" == "1" ]]; then
    "$BUILD_DIR/cassctl" activate \
      --profile "$PROFILE" \
      --identity-common-name "$CASS_IDENTITY_COMMON_NAME" \
      --home "$HOME_DIR" \
      --repo "$REPO_DIR" \
      --verifier "$VERIFIER_PATH" \
      --memory-control "$MEMORY_CONTROL" \
      --runtime-root "$RUNTIME_ROOT"
  fi
fi

cat <<EOF
Prepared CASS gate inputs:
  profile:         $PROFILE
  memory_control:  $MEMORY_CONTROL
  unsigned_policy: $UNSIGNED_POLICY_PATH
EOF

if [[ -f "$SIGNED_POLICY_PATH" ]]; then
  echo "  signed_policy:   $SIGNED_POLICY_PATH"
else
  echo "  signed_policy:   not generated (set CASS_IDENTITY_COMMON_NAME)"
fi

cat <<EOF
  runtime_root:    $RUNTIME_ROOT

Next steps:
  1. Verify token-backed identities:
       $BUILD_DIR/cassctl yubikey list-identities
  2. Install and validate the promotion gate:
       $BUILD_DIR/cassctl doctor --identity-common-name "<YubiKey common name>"
  3. Promote from scratch space into the canonical repo:
       $BUILD_DIR/cassctl promote --source /tmp/candidate.py --target "$REPO_DIR/path/to/file.py"
  4. If Apple approves Endpoint Security later, run the optional overlay checks:
       $BUILD_DIR/cassctl doctor --apple-es --identity-common-name "<YubiKey common name>"
  5. If the host app is installed in /Applications, request the optional Apple overlay:
       CASS_IDENTITY_COMMON_NAME="<YubiKey common name>" CASS_ACTIVATE=1 $0

Notes:
  - The default Phase 1 path is scratch clone + gated promotion.
  - The canonical repo should be promoted into through cassctl, not edited directly by Claude.
  - Apple Endpoint Security is now an optional Phase 2 hardening layer.
  - Token-backed YubiKey identities are discovered through Keychain / CryptoTokenKit and signed through the direct libykpiv backend when available.
  - Default PIN lookup service: com.orxaq.cass.yubikey.piv.pin
  - Default PUK lookup service: com.orxaq.cass.yubikey.piv.puk
  - Apple Watch approval is intentionally deferred to Phase 2.
EOF
