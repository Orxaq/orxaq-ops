# Architecture

This folder explains the current CASS architecture in plain English.

This folder is the conceptual view. Product and platform docs remain canonical
in `../orxaq/docs/`; this repo owns the autonomy/control-plane/CASS layer.

The primary path is now Apple-free:

- Claude works in scratch space.
- The canonical repo is updated through gated promotion.
- Policy changes and breakglass leases are signed with the YubiKey.

Apple Endpoint Security and Apple Watch approval are still documented, but only as optional later layers.

## Recommended Reading Order

1. [CASS In Plain English](cass-kernel-gate-plain-english.md)
2. [CASS Status Summary](cass-kernel-gate-status-summary.md)
3. [CASS Kernel Gate Overview](cass-kernel-gate-overview.md)
4. [CASS Component Map](cass-kernel-gate-components.md)
5. [CASS Readiness And Gap Ledger](cass-kernel-gate-readiness.md)

## What This Folder Is For

This folder answers three questions:

- What is the system supposed to do?
- Which part of the repo is responsible for each part of that behavior?
- Which parts are implemented, which parts are optional, and which parts still depend on Apple-managed prerequisites?

## CASS-Specific Scope

The CASS documentation in this folder covers the current control model for Claude Code on this machine:

- a signed policy that defines what Claude is allowed to touch
- a YubiKey-backed signing path for policy changes and breakglass leases
- a scratch-clone plus gated-promotion path for updating the canonical repo
- an optional Endpoint Security enforcer and host app + system extension deployment shape for macOS

The operational runbook still lives at [docs/cass-kernel-gate.md](../cass-kernel-gate.md). The difference is:

- `docs/architecture/*` explains the system
- `docs/cass-kernel-gate.md` explains how to operate it

## Current Status In One Paragraph

The repo now contains the policy engine, YubiKey-aware signing and lease flows, the `cassctl` admin CLI, signed-policy installation, gated promotion into canonical paths, and the optional Endpoint Security scaffold. The YubiKey PIV identity is live on this machine and CASS can sign through a direct `libykpiv` backend after Keychain discovery. The Apple-specific deployment path still exists, but it is no longer the foundation of the design.
