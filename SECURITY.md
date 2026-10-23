# Security Policy

## Supported versions

Only the latest release is supported. Fixes land on `main` and ship in the next tag.

## Reporting a vulnerability

Open a [private security advisory](https://github.com/RYF5584/WXDBDump-Android/security/advisories/new)
or contact the maintainer directly (see the README). Please do not open a public issue for
anything that could expose a user's data.

Include what you did, what happened, and what you expected. A log captured with
`tools/logcat.sh` helps; it contains paths and key lengths, never key material or message
content.

## Threat model

This tool reads WeChat's private databases on a device the user controls. It is built for
someone extracting their **own** data from their **own** phone. It is not designed to
resist a hostile device.

### What the design protects against

- **Other devices on the network.** The Xposed module's server binds to `127.0.0.1` only.
  Nothing is reachable from the LAN or over USB.
- **Other apps on the same device (ephemeral token + kernel UID check).** There is no
  build-time static `Channel.TOKEN`. Before each loopback connection, the companion app
  generates a fresh 256-bit one-time token bound to the connection's `HELLO` nonce in
  memory (`TokenStore`). When the module inside WeChat receives `HELLO`, it consumes that
  token from the companion app's `AuthTokenProvider` over Android Binder IPC:
  - `AuthTokenProvider` verifies `Binder.getCallingUid()` (supplied by the Linux kernel
    Binder driver and unforgeable by user-space processes) and refuses any caller whose UID
    does not belong to `com.tencent.mm`.
  - Each token is atomically erased on first read (burn-on-read) and expires after 15
    seconds if unused.
- **Repackaged or spoofed companion apps (same-signer APK check).** Before requesting a
  token or answering a handshake, `PeerAuth` inside WeChat checks that the installed
  `io.github.ryf5584.wxdbdump` package carries the exact same signing certificate (SHA-256
  digest) as the Xposed module APK injected by LSPosed.
- **A fake module.** Both directions of the HMAC-SHA256 challenge-response must pass over
  the per-connection one-time token before any command is sent or served.
- **Passive log readers.** Keys are logged by length and source only; the key material,
  ephemeral handshake tokens, and message content never reach logcat.

### Practical guidance

- Both **root mode** and **Xposed mode** authenticate their channel boundaries on the
  local device.
- Uninstall or disable the module when you are not using it.

## Scope

Out of scope: issues that require an already-compromised device or root shell (an attacker
with root can read the same databases directly), and anything that requires physical access
to an unlocked phone.
