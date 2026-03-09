# CASS Status Summary

## Done

- `strict` and `collaborator` policy profiles exist.
- `MEMORY.md` is intentionally excluded in Phase 1.
- breakglass leases exist.
- the YubiKey is provisioned for CASS:
  - `9a` `Orxaq CASS Authentication`
  - `9c` `Orxaq CASS Policy`
  - `9d` `Orxaq CASS Key Management`
- PIN and PUK are no longer defaults.
- policy signing works through the direct `libykpiv` path.
- a current strict policy exists at `state/cass/claude-code-strict.policy.json`
- a signed strict policy exists at `state/cass/claude-code-strict.policy.signed.json`
- `cassctl install-policy` installs a signed policy into the runtime root.
- `cassctl promote` gates promotion from candidate file to canonical target through the verifier and lease logic.
- `create_scratch_clone.sh` creates a disposable repo with CASS metadata.
- `run_claude_in_scratch.sh` creates the scratch repo and starts Claude there.
- `promote_scratch_changes.sh` promotes changed files from scratch back into the canonical repo through `cassctl`.
- the live Claude hook wiring in `orxaq/.claude/settings.local.json` now routes through `scratch_session_gate.sh`
- canonical repo direct `Edit` and `Write` are blocked
- canonical repo `Bash` is now read-only except for the CASS scratch and promotion commands
- scratch sessions can edit only inside the scratch repo and cannot target canonical repo paths except through promotion
- the Swift test suite covers policy generation, path matching, dangerous commands, verification gating, leases, and signing.

## Primary path now

Primary path is no longer Apple-first.

It is:

1. Claude edits a scratch clone or candidate file.
2. CASS evaluates promotion into the canonical repo.
3. passing changes are promoted
4. failing changes are denied

That path works without Apple approval.

## Not done

- the runtime root still needs to be created and owned the way you want on the final machine
- a full live Claude session should be run through `run_claude_in_scratch.sh` as the new default habit
- more adversarial testing is still possible, but the primary gating path is now wired

## Optional later layer

These are optional now, not required for Phase 1:

- Apple Developer team assets
- managed Endpoint Security entitlement
- host app in `/Applications`
- system extension approval
- Apple Watch approval flow

If Apple approves later, that becomes an extra hardening layer on top of the same policy, lease, and YubiKey model.

## What you would do

Normally: nothing.

When stepping in:

- touch the YubiKey to sign a policy change
- touch the YubiKey to sign a breakglass lease
- repair the verifier or promotion pipeline if it breaks
