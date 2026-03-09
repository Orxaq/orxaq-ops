# CASS Control App

This directory contains the optional macOS hardening layer for CASS:

- `CASSControl` is the host app that belongs in `/Applications`.
- `CASSEnforcer` is the Endpoint Security system extension bundle.
- `project.yml` is an XcodeGen template that wires both targets against the shared Swift package in `tools/cass-kernel-gate`.

It is no longer the primary path.

The primary path is scratch-clone plus gated promotion with YubiKey-signed policy.

This Apple layer stays here for later, if you want extra kernel-level blocking on macOS.

It still cannot be activated on this machine without:

1. an Apple Developer team,
2. the managed Endpoint Security entitlement from Apple,
3. provisioning assets for the app and system extension,
4. YubiKey-backed policy signing for the active policy envelope.

## Optional Activation Flow

1. Generate the Xcode project from `project.yml`.
2. Replace the bundle identifiers and signing team placeholders with real Apple Developer values.
3. Build the app and system extension.
4. Install `CASS Control.app` into `/Applications`.
5. Run `cassctl activate --profile strict --identity-common-name <YubiKey common name>`.
6. Let the host app submit the system-extension activation request through `OSSystemExtensionRequest`.

The host app expects activation requests from `cassctl` via:

- `--cass-activate-request <path>`
- `--cass-deactivate`
