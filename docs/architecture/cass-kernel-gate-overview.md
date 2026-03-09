# CASS Overview

## Current architecture

Primary architecture:

- scratch workspace for Claude
- canonical repo protected by promotion gate
- YubiKey-signed policy
- YubiKey-signed breakglass leases
- verifier-gated promotion for governed Python files

Optional later architecture:

- macOS host app
- Endpoint Security system extension
- Apple Watch approval

## Trust boundary

The trust boundary is no longer "whatever Apple approves."

It is now:

- the canonical repo
- the runtime root
- the verifier
- the signing key on the YubiKey

Claude should be treated as untrusted with respect to canonical state.

## Enforcement model

The main rule is:

- candidate content is produced somewhere else
- promotion into canonical state is the only privileged write

For governed Python paths:

1. direct writes are denied
2. candidate file is checked
3. promotion is allowed only if verification passes

For protected governance and evidence paths:

- governed path rules deny writes or destructive operations

For dangerous shell commands:

- governed command rules deny execution

For temporary exceptions:

- a breakglass lease can override normal denial for a narrow path and operation set

## Operator model

Normal operation:

- no approvals
- no daily prompts

Operator action:

- touch YubiKey to sign policy change
- touch YubiKey to sign breakglass lease

## What Apple still means

Apple now means:

- optional Phase 2 hardening
- kernel-level blocking on macOS if approved

Apple no longer means:

- required for the basic CASS control model
- required for YubiKey-backed policy authority
