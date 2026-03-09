# CASS Component Map

## 1. Policy model

Files:

- [PolicyModels.swift](../../tools/cass-kernel-gate/Sources/CassPolicyCore/PolicyModels.swift)
- [PolicyFactory.swift](../../tools/cass-kernel-gate/Sources/CassPolicyCore/PolicyFactory.swift)

This layer defines:

- `strict`
- `collaborator`
- governed path rules
- governed command rules
- verification rules
- breakglass lease shape

## 2. Policy engine

File:

- [PolicyEngine.swift](../../tools/cass-kernel-gate/Sources/CassPolicyCore/PolicyEngine.swift)

This is the decision-maker.

It answers:

- does this command get denied?
- does this path operation get denied?
- does this governed Python promotion need verification?
- is there an active lease that overrides the deny?

## 3. Path handling

File:

- [PathMatcher.swift](../../tools/cass-kernel-gate/Sources/CassPolicyCore/PathMatcher.swift)

This handles:

- glob matching
- path normalization
- symlink-aware candidate matching

## 4. Signing

Files:

- [Signing.swift](../../tools/cass-kernel-gate/Sources/CassPolicyCore/Signing.swift)
- [DirectYubiKeySigner.swift](../../tools/cass-kernel-gate/Sources/CassPolicyCore/DirectYubiKeySigner.swift)

This layer handles:

- identity discovery
- YubiKey signing
- policy signature verification
- lease signature verification

The important point is:

- token-backed identities are discovered through Keychain / CryptoTokenKit
- direct `libykpiv` signing is used for the actual hardware-backed signing path when available

## 5. Runtime root and audit

File:

- [RuntimeSupport.swift](../../tools/cass-kernel-gate/Sources/CassPolicyCore/RuntimeSupport.swift)

This layer handles:

- runtime directory layout
- audit logging
- lease storage
- active-lease loading

## 6. Operator CLI

File:

- [main.swift](../../tools/cass-kernel-gate/Sources/cassctl/main.swift)

Important commands now:

- `cassctl doctor`
- `cassctl status`
- `cassctl install-policy`
- `cassctl promote`
- `cassctl policy sign`
- `cassctl lease create`
- `cassctl lease list`
- `cassctl lease revoke`
- `cassctl yubikey list-identities`
- `cassctl yubikey doctor`

The new important change is that `install-policy` and `promote` make the Apple-free path operational.

## 7. Optional Apple layer

Files:

- [EndpointSecurityDaemon.swift](../../tools/cass-kernel-gate/Sources/CassEndpointSecuritySupport/EndpointSecurityDaemon.swift)
- [project.yml](../../apps/cass-control/project.yml)
- [CASSControlApp.swift](../../apps/cass-control/CASSControl/Sources/CASSControlApp.swift)
- [SystemExtensionCoordinator.swift](../../apps/cass-control/CASSControl/Sources/SystemExtensionCoordinator.swift)
- [main.swift](../../apps/cass-control/CASSEnforcer/Sources/main.swift)

This is still in the repo.

It is now an optional later overlay, not the primary system design.
