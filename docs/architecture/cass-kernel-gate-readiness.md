# CASS Readiness

## Ready now

- policy generation
- YubiKey-backed signing
- lease signing
- signed policy install into runtime root
- promotion decision engine
- verifier-gated promotion
- audit logging
- lease store

## Partially ready

- scratch-clone workflow integration
- canonical repo operational separation from Claude's default workspace
- end-to-end promotion automation

These are design-ready and code-ready enough to wire in, but not yet fully integrated into the actual Claude workflow.

## Optional later

- Apple Endpoint Security runtime
- host app + system extension deployment
- Apple Watch approval

These are intentionally no longer on the critical path.

## Practical next steps

1. Make Claude use scratch space by default.
2. Make successful work call `cassctl promote` instead of writing directly into canonical paths.
3. Keep policy and breakglass signing on YubiKey touch only.
4. Run adversarial tests against the real repo flow.
5. Add Apple Endpoint Security later only if it becomes available and still seems worth the extra complexity.
