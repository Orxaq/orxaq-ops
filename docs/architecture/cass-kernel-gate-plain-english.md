# CASS In Plain English

## Short version

The new plan is simple:

- Claude should not edit the real repo directly.
- Claude should work in scratch space.
- Clean changes should promote automatically into the real repo.
- Rule changes and emergency overrides should require a YubiKey touch.

That is the default path now.

Apple Endpoint Security is optional later. It is no longer the thing CASS depends on to be useful.

## Why the design changed

The old plan made Apple part of the trust boundary.

That was a problem because the whole point was to avoid depending on another company for the core guarantee.

So the design changed from:

- "make the Mac kernel stop Claude"

to:

- "make Claude work somewhere disposable and only let verified results into the canonical repo"

## What this means in practice

There are now two important places:

### 1. Scratch space

This is where Claude works.

Claude can edit, try things, run tools, and generate candidate files there.

Scratch space is disposable.

### 2. Canonical repo

This is the real repo you care about.

Claude should not write there directly.

Instead, a promotion step decides whether a candidate file is allowed to replace the real target.

## What decides whether promotion is allowed

Three things:

### Policy

The policy says what is protected and what is denied.

Examples:

- settings files
- hook scripts
- repo rule files
- evidence paths
- dangerous shell commands
- Python files that must pass verification before promotion

### Verifier

For governed Python paths, direct in-place writes are denied.

A candidate file has to pass the verifier before it can be promoted into the real repo path.

### Breakglass

If you need a temporary exception, you sign a short breakglass lease with the YubiKey.

That lease can allow a specific path and operation for a short time.

## What you would actually experience

Most of the time:

- Claude works
- checks run
- passing changes promote
- you do nothing

If something is blocked:

- Claude stays blocked
- no routine approval request appears

If you want to change the rules:

- you touch the YubiKey once

If you want a temporary override:

- you touch the YubiKey once

That is the whole operator loop.

## What is protected in strict mode

Strict mode protects:

- your global Claude instruction and settings files
- repo Claude governance files
- repo hook and rules files
- repo agent and MCP files
- violation records
- the governed harness plan

It also:

- blocks dangerous command patterns
- denies direct writes to governed Python targets
- requires staged promotion for governed Python files

It does not currently lock `MEMORY.md`.

## What collaborator mode means

Collaborator mode is lighter.

It protects repo governance, but not your personal machine-level Claude files and not your personal evidence paths.

So:

- `strict` = your machine boundary
- `collaborator` = repo boundary

## What is already real

These parts already work:

- YubiKey provisioning
- YubiKey-backed policy signing
- signed policies
- signed breakglass leases
- policy installation into the runtime root
- promotion decisions through the policy engine
- verifier-gated promotion for governed Python paths

## What is still not finished

Two things remain:

### 1. Workflow wiring

Claude still needs to be pointed at scratch space by default, with promotion wired into the actual working loop.

### 2. Optional Apple layer

If Apple later approves Endpoint Security, you can add:

- host app
- system extension
- Apple Watch approval

But that is extra hardening, not the foundation.

## The main idea

The real repo becomes something Claude can influence only through a gate.

That is the core guarantee.
