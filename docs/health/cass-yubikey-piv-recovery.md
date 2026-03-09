# CASS YubiKey PIV Recovery

- `status`: `resolved`
- `blocker_reason`: `Initial YubiKey PIV provisioning failed after the PIN, PUK, and management key changed, leaving the token half-configured and unrecoverable without a reset.`
- `escalation_target`: `none`
- `next_action`: `none`

Resolution summary:

- the PIV app was reset
- slots `9a`, `9c`, and `9d` were reprovisioned
- the PIN and PUK were rotated away from defaults and stored in login Keychain
- the management key was rotated to a random AES-256 key and stored on-device behind the PIN
- CryptoTokenKit discovery now sees the token and `cassctl` can sign policies with the direct YubiKey backend
