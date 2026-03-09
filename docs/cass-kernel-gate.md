# CASS Runbook

This is the operator runbook for CASS on this machine.

This document is intentionally machine-local. Absolute paths below are part of
the local operating contract and are not meant to be portable product docs.

Primary path now:

- Claude works in a scratch clone or other disposable workspace.
- The canonical repo is updated only through `cassctl promote`.
- Policy changes and breakglass leases are signed with the YubiKey.
- Apple Endpoint Security is optional Phase 2 hardening, not the default dependency.

Related architecture docs:

- [CASS In Plain English](architecture/cass-kernel-gate-plain-english.md)
- [CASS Status Summary](architecture/cass-kernel-gate-status-summary.md)
- [CASS Overview](architecture/cass-kernel-gate-overview.md)
- [CASS Component Map](architecture/cass-kernel-gate-components.md)
- [CASS Readiness](architecture/cass-kernel-gate-readiness.md)

## Phase 1

Phase 1 is Apple-free by default.

It gives you:

- signed policy generation
- signed breakglass leases
- YubiKey-backed authority
- verifier-gated promotion into the canonical repo
- audit and lease state outside the repo

It does not require:

- Apple Endpoint Security approval
- a host app in `/Applications`
- an Apple Watch

The project-local Claude wiring is now set up so the canonical repo is effectively read-only to Claude:

- direct `Edit`, `Write`, and `MultiEdit` in `/Users/sdevisch/dev/orxaq` are blocked
- canonical-repo `Bash` is read-only except for the CASS scratch and promotion commands
- scratch sessions can only edit inside the scratch repo
- scratch sessions cannot target canonical repo paths directly except through promotion

## Profiles

### `strict`

Protects:

- `/Users/sdevisch/CLAUDE.md`
- `/Users/sdevisch/.claude/settings.json`
- `/Users/sdevisch/.claude/settings.local.json`
- `/Users/sdevisch/dev/orxaq/CLAUDE.md`
- `/Users/sdevisch/dev/orxaq/.claude/settings.json`
- `/Users/sdevisch/dev/orxaq/.claude/settings.local.json`
- `/Users/sdevisch/dev/orxaq/.claude/hooks/*`
- `/Users/sdevisch/dev/orxaq/.claude/rules/**`
- `/Users/sdevisch/dev/orxaq/.claude/agents.md`
- `/Users/sdevisch/dev/orxaq/.claude/agents/**`
- `/Users/sdevisch/dev/orxaq/.claude/mcp.json`
- `/Users/sdevisch/Documents/Orxaq/obsidian_vault/Violations/**`
- `/Users/sdevisch/Documents/Orxaq/obsidian_vault/Plans/claude-code-harness.md`

Also enforces:

- deny `chflags nouchg`
- deny `chmod 7xx`
- deny deletion of violation records
- verifier-gated promotion for `/Users/sdevisch/dev/orxaq/**/*.py`

Still writable in Phase 1:

- `MEMORY.md`
- factual repo `.claude` docs such as `api-routes.md`, `codebase-map.md`, `data-registry.md`, `env-vars.md`, `surface.md`, `test-guide.md`, `training.md`, `troubleshooting.md`

### `collaborator`

Protects only repo governance plus dangerous command denies plus the Python promotion gate.

It does not protect:

- personal `~/` Claude files
- Obsidian evidence paths
- `MEMORY.md`

## Runtime root

Runtime state lives outside the repo:

- `/Library/Application Support/com.orxaq.cass/policies/`
- `/Library/Application Support/com.orxaq.cass/leases/`
- `/Library/Application Support/com.orxaq.cass/audit/`
- `/Library/Application Support/com.orxaq.cass/status/`

Important files:

- active policy: `/Library/Application Support/com.orxaq.cass/policies/active-policy.signed.json`
- leases: `/Library/Application Support/com.orxaq.cass/leases/*.signed.json`
- audit log: `/Library/Application Support/com.orxaq.cass/audit/audit.jsonl`
- status: `/Library/Application Support/com.orxaq.cass/status/current.json`

## Main commands

Build:

```bash
cd /Users/sdevisch/dev/orxaq-ops/tools/cass-kernel-gate
swift build
```

List YubiKey identities:

```bash
swift run cassctl yubikey list-identities
```

Doctor the default Apple-free path:

```bash
swift run cassctl doctor --identity-common-name "Orxaq CASS Policy"
```

Generate a policy:

```bash
swift run cass-policy init-claude \
  --home /Users/sdevisch \
  --repo /Users/sdevisch/dev/orxaq \
  --verifier /Users/sdevisch/dev/orxaq/.claude/hooks/cass_code_verify.sh \
  --profile strict \
  --memory-control disabled \
  --output /tmp/claude.strict.policy.json
```

Sign it with the YubiKey:

```bash
swift run cassctl policy sign \
  --policy /tmp/claude.strict.policy.json \
  --output /tmp/claude.strict.policy.signed.json \
  --identity-common-name "Orxaq CASS Policy"
```

Install it into the runtime root:

```bash
sudo swift run cassctl install-policy \
  --signed-policy /tmp/claude.strict.policy.signed.json
```

Promote a candidate file into the canonical repo:

```bash
sudo swift run cassctl promote \
  --source /tmp/candidate.py \
  --target /Users/sdevisch/dev/orxaq/path/to/file.py
```

Dry-run a promotion decision:

```bash
swift run cassctl promote \
  --source /tmp/candidate.py \
  --target /Users/sdevisch/dev/orxaq/path/to/file.py \
  --dry-run
```

Create a 15-minute breakglass lease:

```bash
swift run cassctl lease create \
  --identity-common-name "Orxaq CASS Policy" \
  --profile strict \
  --paths "/Users/sdevisch/.claude/settings.json" \
  --ops open_write \
  --duration 15m \
  --reason "temporary operator override"
```

List or revoke leases:

```bash
swift run cassctl lease list
swift run cassctl lease revoke --lease-id <lease-id> --reason "done"
```

## Hands-off flow

Default flow:

1. Claude edits a scratch clone.
2. Automation runs checks.
3. Clean changes are promoted with `cassctl promote`.
4. You do nothing.

You step in only to:

- touch the YubiKey for a policy change
- touch the YubiKey for a breakglass lease
- repair the verifier or promotion pipeline if it breaks

## Optional Phase 2

Apple-specific hardening stays available later:

- host app in `/Applications`
- Endpoint Security system extension
- Apple-managed entitlement
- Apple Watch approval path

That layer is optional. It is no longer the foundation of the design.

If Apple approves later, use:

```bash
swift run cassctl doctor --apple-es --identity-common-name "Orxaq CASS Policy"
swift run cassctl activate --profile strict --identity-common-name "Orxaq CASS Policy"
```

## Helper script

The helper script now prepares and installs the signed policy for the promotion gate by default:

```bash
/Users/sdevisch/dev/orxaq-ops/scripts/cass/install_claude_cass_gate.sh
```

Scratch workflow helpers:

```bash
/Users/sdevisch/dev/orxaq-ops/scripts/cass/create_scratch_clone.sh
/Users/sdevisch/dev/orxaq-ops/scripts/cass/run_claude_in_scratch.sh
/Users/sdevisch/dev/orxaq-ops/scripts/cass/promote_scratch_changes.sh
```

Typical loop:

1. create a scratch clone
2. run Claude inside that scratch repo
3. promote changed files back through `cassctl`

One-command entrypoint:

```bash
/Users/sdevisch/dev/orxaq-ops/scripts/cass/run_claude_in_scratch.sh /Users/sdevisch/dev/orxaq
```

If `CASS_ACTIVATE=1` is set, it also requests the optional Apple Endpoint Security activation path.
