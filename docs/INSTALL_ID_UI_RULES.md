# Install ID UI Rules

## Purpose

PiPass uses a per-install `installId` to help correlate audit activity with a specific app installation. This document defines how future UI should describe that value without implying security guarantees it does not provide.

These rules apply to security dashboards, device/session screens, audit views, recovery messaging, and any future "this device" or "this install" UI.

## What installId is

- `installId` is a non-secret, locally persisted label for one PiPass app install.
- The client creates it randomly on first use and sends it as `x-install-id` on protected API requests.
- The server accepts it only as optional UUID-shaped metadata.
- Valid values may appear in safe audit metadata to help correlate activity.
- Missing or invalid values are treated as absent and must not block authentication, vault access, recovery, or normal app use.

## What installId is not

`installId` is not:

- a secret
- a recovery code
- a trusted credential
- a device-authentication proof
- a biometric proof
- an encryption factor
- a key-derivation input
- a vault-access decision
- a replacement for server-side device trust
- a reliable identity guarantee

It is spoofable. Any client can claim an `installId`, so the UI must never present it as proof that a device is genuine or safe.

## Safe UI Wording

Use wording that presents installId as a label or correlation hint:

- "This app install"
- "Install label"
- "Install activity"
- "Seen from this install"
- "Activity with install label ending in 1234"
- "This label helps match audit events from the same app install."

If shown directly, display only a shortened value, such as the first or last 6-8 characters. Avoid showing the full UUID unless a developer/debug view explicitly needs it.

## Unsafe UI Wording

Avoid wording that implies proof, trust, or secrecy:

- "Verified device"
- "Trusted by install ID"
- "Secure device ID"
- "Device secret"
- "Recovery install code"
- "Biometric verified install"
- "Encryption-bound device"
- "Approve this device using install ID"
- "Share this install ID with support to recover your vault"

Never ask a user to copy, save, share, or treat `installId` as a secret.

## Relationship To Trusted Devices And Sessions

PiPass has several separate concepts:

- `installId`: a non-secret app-install label supplied by the client for audit context.
- Session/device fingerprint: a server-side security signal derived from request context, used for anomaly and device tracking.
- Trusted device/session state: explicit server-side state showing whether a session or device has been trusted.
- Audit event metadata: safe descriptive context attached to security events.

Only server-side trust state may justify UI wording such as "trusted" or "untrusted." An installId alone must never approve a device, bypass a gate, mark a session trusted, or downgrade a warning.

## Relationship To Biometrics

Biometric unlock is a local convenience gate. It may protect local access to stored keys or app actions on the device, but it is not server proof.

Do not combine biometric language with installId in a way that implies the server verified the person or device. For example, avoid "Face ID verified install." Prefer separate wording:

- "Unlocked locally with biometrics"
- "Activity from this app install"

## Audit-Log Usage

Audit views may use installId metadata to help users correlate events, for example:

- multiple events from the same app install
- a new device/session followed by vault sync attempts
- trusted-device changes made from the same install label

Audit UI must still preserve existing hygiene:

- never show auth hashes
- never show encrypted vault blobs
- never show plaintext vault data
- never show request headers or request bodies
- never show cookies, session tokens, database URLs, or secrets
- never show passkey public-key internals

If installId is missing or invalid, show no install label rather than an error.

## Future UI Checklist

Before shipping UI that displays install/device identity information:

- Label installId as "Install label" or "This app install."
- Show only a shortened installId if shown at all.
- Explain that the label helps correlate activity, not prove identity.
- Use "trusted" only when server-side trusted device/session state says trusted.
- Keep installId out of encryption, key derivation, biometrics, auth, recovery, and vault-access decisions.
- Do not use installId alone to approve or trust a device.
- Do not ask the user to copy or share installId as a secret.
- Treat missing or invalid installId as absent.
- Keep audit responses and UI free of secrets and request data.
