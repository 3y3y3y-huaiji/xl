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

- **Zero open network or abstract socket ports.** Neither the app nor the Xposed module
  opens a TCP port or a `LocalServerSocket`, and the app does not request
  `android.permission.INTERNET`.
- **Other apps on the same device (kernel `AF_UNIX` SocketPair over Binder + UID check).**
  While Android SELinux MLS/MCS isolation forbids cross-UID `connectto` on an abstract
  `LocalServerSocket`, AOSP SELinux permits passing an already-connected
  `unix_stream_socket` file descriptor (`ParcelFileDescriptor.createSocketPair()`) over
  Android Binder IPC:
  - When the companion app requests a session, `PeerAuth` inside WeChat verifies that the
    installed `io.github.ryf5584.wxdbdump` APK carries the exact same signing certificate
    (SHA-256) as the Xposed module APK injected by LSPosed.
  - `PeerAuth` creates a dedicated kernel `AF_UNIX` stream socket pair and passes the
    client descriptor to `SocketBridgeProvider` via `ContentResolver.call()`.
  - `SocketBridgeProvider` checks `Binder.getCallingUid()` (supplied by the Linux kernel
    Binder driver) and only accepts descriptors from `com.tencent.mm`, returning a
    single-use 256-bit token in the Binder reply.
  - Both sides then run a mutual HMAC-SHA256 challenge-response over that single-use token
    before any command is sent or served.
- **Passive log readers.** Keys are logged by length and source only; the key material,
  ephemeral handshake tokens, and message content never reach logcat.

### Practical guidance

- Both **root mode** and **Xposed mode** authenticate their channel boundaries at the OS
  kernel and APK signature level without opening any listening port.
- Uninstall or disable the module when you are not using it.

## Scope

Out of scope: issues that require an already-compromised device or root shell (an attacker
with root can read the same databases directly), and anything that requires physical access
to an unlocked phone.
