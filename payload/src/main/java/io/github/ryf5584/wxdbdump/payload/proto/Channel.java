package io.github.ryf5584.wxdbdump.payload.proto;

/**
 * Unix domain SocketPair + Binder channel constants shared by the app and the Xposed module.
 *
 * <p>Instead of opening a TCP loopback port on {@code 127.0.0.1} or relying on a static
 * build-time token, this channel establishes an authenticated kernel {@code AF_UNIX}
 * stream socket pair ({@code ParcelFileDescriptor.createSocketPair()}) per session over
 * Android Binder IPC:
 * <ol>
 *   <li>The app registers a short-lived single-use {@code requestId} in
 *       {@code SocketBridgeProvider} and wakes the module inside WeChat via an explicit
 *       foreground broadcast ({@link #ACTION_CONNECT}).</li>
 *   <li>The module inside WeChat verifies that the installed {@link #APP_PACKAGE} APK
 *       carries the exact same signing certificate (SHA-256) as the injected module APK,
 *       creates an {@code AF_UNIX} socket pair, and hands the client file descriptor to
 *       {@link #BRIDGE_AUTHORITY} via {@code ContentResolver.call()}.</li>
 *   <li>{@code SocketBridgeProvider} verifies {@code Binder.getCallingUid()} belongs to
 *       {@link #WECHAT_PACKAGE}, accepts the socket descriptor, and returns a single-use
 *       256-bit session token in the Binder reply.</li>
 *   <li>Both ends immediately close the unused descriptor copy and run the mutual HMAC
 *       handshake and {@link Wire} framing over the private kernel socket pair.</li>
 * </ol>
 */
public final class Channel {

    /** Transport descriptor shown in diagnostics (no TCP port is opened). */
    public static final String TRANSPORT_LABEL = "unix-socketpair://binder";

    /** Host application package name. */
    public static final String APP_PACKAGE = "io.github.ryf5584.wxdbdump";

    /** Target WeChat package name. */
    public static final String WECHAT_PACKAGE = "com.tencent.mm";

    /** Binder ContentProvider authority brokering AF_UNIX socket pairs and one-time tokens. */
    public static final String BRIDGE_AUTHORITY = APP_PACKAGE + ".bridge";

    /** Content URI used for URI permission grants (Android 11+ visibility) and Binder calls. */
    public static final String BRIDGE_URI = "content://" + BRIDGE_AUTHORITY + "/session";

    /** Explicit broadcast action sent to WeChat to request a fresh AF_UNIX socket pair. */
    public static final String ACTION_CONNECT = APP_PACKAGE + ".action.CONNECT";

    /** Broadcast Intent extra carrying the one-time connection request id. */
    public static final String EXTRA_REQUEST_ID = "request_id";

    /** ContentProvider.call() method invoked by the module inside WeChat to attach a socket pair. */
    public static final String BRIDGE_METHOD_ATTACH = "attach_socket";

    /** Bundle key holding the ParcelFileDescriptor for the companion app end of the socket pair. */
    public static final String BRIDGE_KEY_FD = "fd";

    /** Bundle key holding the single-use 256-bit handshake token returned by the provider. */
    public static final String BRIDGE_KEY_TOKEN = "token";

    /** Client version, reported in HELLO. */
    public static final String CLIENT_VERSION = "1.0.0";

    private Channel() {
    }
}
